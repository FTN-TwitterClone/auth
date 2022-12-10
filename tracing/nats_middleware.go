package tracing

import (
	"github.com/nats-io/nats.go"
	"go.opentelemetry.io/otel/trace"
)

const (
	TRACE_ID = "TRACE_ID"
	SPAN_ID  = "SPAN_ID"
)

func GetNATSParentContext(msg *nats.Msg) (spanContext trace.SpanContext, err error) {
	var traceID trace.TraceID
	traceID, err = trace.TraceIDFromHex(msg.Header.Get(TRACE_ID))
	if err != nil {
		return spanContext, err
	}
	var spanID trace.SpanID
	spanID, err = trace.SpanIDFromHex(msg.Header.Get(SPAN_ID))
	if err != nil {
		return spanContext, err
	}
	var spanContextConfig trace.SpanContextConfig
	spanContextConfig.TraceID = traceID
	spanContextConfig.SpanID = spanID
	spanContextConfig.TraceFlags = 01
	spanContextConfig.Remote = true
	spanContext = trace.NewSpanContext(spanContextConfig)
	return spanContext, nil
}
