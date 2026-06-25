package certwebhook

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

var tracer trace.Tracer

func initTracer() {
	tracer = otel.Tracer("cert_webhook")
}

func startSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	if tracer == nil {
		initTracer()
	}
	return tracer.Start(ctx, name, trace.WithAttributes(attrs...))
}

func endSpanWithError(span trace.Span, err error) {
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)
	}
	span.End()
}
