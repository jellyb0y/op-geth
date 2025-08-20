// eth/tracers/native/call_logs_tracer.go
package native

import (
	"encoding/json"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/tracers"
)

// ---------- JSON форматы результата (порядок полей соответствует JS callTracer) ----------

type eventLog struct {
	Address common.Address `json:"address"`
	Topics  []common.Hash  `json:"topics"`
	Data    hexutil.Bytes  `json:"data"`
}

type call struct {
	Type    string          `json:"type,omitempty"`
	From    common.Address  `json:"from,omitempty"`
	To      *common.Address `json:"to,omitempty"`
	Value   *hexutil.Big    `json:"value,omitempty"`
	Gas     *hexutil.Uint64 `json:"gas,omitempty"`
	GasUsed *hexutil.Uint64 `json:"gasUsed,omitempty"`
	Input   hexutil.Bytes   `json:"input,omitempty"`
	Output  *hexutil.Bytes  `json:"output,omitempty"`
	Error   string          `json:"error,omitempty"`
	Logs    []eventLog      `json:"logs,omitempty"`
	Calls   []*call         `json:"calls,omitempty"`
}

// ---------- внутренний фрейм стека ----------

type frame struct {
	call
	// временные поля, не попадают в JSON
	depth int
	// признак CREATE/CREATE2
	isCreate bool
}

// ---------- сам трейсер ----------

type callLogsTracer struct {
	hooks *tracing.Hooks
	// стек активных фреймов
	stack []*frame
	// вершина результата (outermost call)
	root *call
	// VM контекст, нужен для доступа к стейту в некоторых опкодах
	vmc *tracing.VMContext
}

func (t *callLogsTracer) Hooks() *tracing.Hooks { return t.hooks }

// GetResult сериализует итог
func (t *callLogsTracer) GetResult() (json.RawMessage, error) {
	if t.root == nil {
		// Пустой ответ вместо null, чтобы RPC-клиенты не спотыкались
		return json.Marshal(call{})
	}
	return json.Marshal(t.root)
}

// Stop — сигнал тайм-аута/остановки
func (t *callLogsTracer) Stop(err error) {
	// Ничего: мы и так фиксируем ошибки на Exit/Fault
}

// ---------- конструктор и регистрация ----------

func newCallLogsTracer() tracers.Tracer {
	tr := &callLogsTracer{}
	tr.hooks = &tracing.Hooks{
		OnTxStart: tr.onTxStart,
		OnEnter:   tr.onEnter,
		OnExit:    tr.onExit,
		OnFault:   tr.onFault,
		OnOpcode:  tr.onOpcode, // для LOG0..LOG4 и SELFDESTRUCT
	}
	return tr
}

func init() {
	tracers.DefaultDirectory.Register("callLogsTracer", newCallLogsTracer, false)
}

// ---------- хуки ----------

func (t *callLogsTracer) onTxStart(vmc *tracing.VMContext, _ *tracing.BlockEvent, _ common.Address) {
	t.vmc = vmc
	t.stack = t.stack[:0]
	t.root = nil
}

func (t *callLogsTracer) onEnter(depth int, typ byte, from, to common.Address, input []byte, gas uint64, value *big.Int) {
	// Собираем новый фрейм
	f := &frame{
		depth: depth,
		call: call{
			Type:  vm.OpCode(typ).String(),
			From:  from,
			Input: append(hexutil.Bytes(nil), input...),
			Gas:   (*hexutil.Uint64)(&gas),
		},
	}
	switch vm.OpCode(typ) {
	case vm.CREATE, vm.CREATE2:
		f.isCreate = true
	default:
		// обычный CALL-подобный
		toCopy := to // адрес в heap, чтобы &toCopy был стабильным
		f.To = &toCopy
	}
	// value только для CALL/CALLCODE/CREATE*_ (не для DELEGATE/STATIC)
	switch vm.OpCode(typ) {
	case vm.CALL, vm.CALLCODE, vm.CREATE, vm.CREATE2:
		if value != nil {
			v := (*hexutil.Big)(new(hexutil.Big))
			*v = hexutil.Big(*value)
			f.Value = v
		}
	}

	t.stack = append(t.stack, f)
}

func (t *callLogsTracer) onExit(depth int, output []byte, gasUsed uint64, err error, reverted bool) {
	if len(t.stack) == 0 {
		return
	}
	// снимаем верхушку (последний фрейм с совпадающей глубиной)
	f := t.stack[len(t.stack)-1]
	t.stack = t.stack[:len(t.stack)-1]

	// gasUsed
	if gasUsed > 0 {
		gu := hexutil.Uint64(gasUsed)
		f.GasUsed = &gu
	}

	// output:
	// - для обычных CALL — return data
	// - для CREATE/CREATE2 — возвращённый код
	if len(output) > 0 {
		out := hexutil.Bytes(append([]byte(nil), output...))
		f.Output = &out
	}

	// ошибка/реверт
	if reverted && err == nil {
		f.Error = "execution reverted"
	} else if err != nil {
		f.Error = err.Error()
	}

	// Вкладываем фрейм в родителя или считаем корнем
	if len(t.stack) == 0 {
		// это outermost
		c := f.call // отбрасываем внутренние поля
		t.root = &c
	} else {
		p := t.stack[len(t.stack)-1]
		p.Calls = append(p.Calls, &f.call)
	}
}

func (t *callLogsTracer) onFault(depth int, op byte, _ uint64, _ uint64, _ tracing.OpContext, _ []byte, err error) {
	// Ошибка на opcode уровне до Exit — пометим активный фрейм
	if len(t.stack) == 0 {
		return
	}
	f := t.stack[len(t.stack)-1]
	if f.Error == "" && err != nil {
		f.Error = err.Error()
	}
}

func (t *callLogsTracer) onOpcode(pc uint64, op byte, gas uint64, cost uint64, scope tracing.OpContext, rdata []byte, depth int, _ error) {
	code := vm.OpCode(op)

	// Логи: LOG0..LOG4
	if code >= vm.LOG0 && code <= vm.LOG4 {
		n := int(code - vm.LOG0) // число топиков
		stack := scope.StackData()
		mem := scope.MemoryData()

		// Позиции на стеке (сверху вниз): topicN ... topic1, mSize, mStart
		if len(stack) < n+2 {
			return
		}
		top := len(stack) - 1
		mSizeU := stack[top-n-0].Uint64()
		mStartU := stack[top-n-1].Uint64()

		var data hexutil.Bytes
		if int(mStartU)+int(mSizeU) <= len(mem) {
			data = hexutil.Bytes(append([]byte(nil), mem[mStartU:mStartU+mSizeU]...))
		} else {
			// Защита от выходов за память
			data = hexutil.Bytes{}
		}
		topics := make([]common.Hash, 0, n)
		for i := 0; i < n; i++ {
			topics = append(topics, common.BigToHash(stack[top-i].ToBig()))
		}

		// адрес контракта = текущий аккаунт исполнения
		addr := scope.Address()

		elog := eventLog{
			Address: addr,
			Topics:  topics,
			Data:    data,
		}
		if len(t.stack) > 0 {
			f := t.stack[len(t.stack)-1]
			f.Logs = append(f.Logs, elog)
		}
		return
	}

	// SELFDESTRUCT: добавим как "вложенный вызов" для наглядности (как в JS-трейсере)
	if code == vm.SELFDESTRUCT && len(t.stack) > 0 {
		stack := scope.StackData()
		if len(stack) < 1 {
			return
		}
		beneficiary := common.BigToAddress(stack[len(stack)-1].ToBig())
		from := scope.Address()

		// Считаем value = текущий баланс контракта (как в JS-варианте)
		var val *hexutil.Big
		if t.vmc != nil && t.vmc.StateDB != nil {
			b := t.vmc.StateDB.GetBalance(from)
			hb := (*hexutil.Big)(new(hexutil.Big))
			*hb = hexutil.Big(*b)
			val = hb
		}

		sub := &call{
			Type:  "SELFDESTRUCT",
			From:  from,
			To:    &beneficiary,
			Value: val,
			// gas/gasUsed здесь особого смысла нет; можно опустить
		}
		parent := t.stack[len(t.stack)-1]
		parent.Calls = append(parent.Calls, sub)
	}
}
