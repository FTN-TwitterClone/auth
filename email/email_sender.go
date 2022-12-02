package email

import (
	"context"
	"fmt"
	"go.opentelemetry.io/otel/trace"
	"net/smtp"
	"os"
)

type EmailSender struct {
	tracer trace.Tracer
}

func NewEmailSender(tracer trace.Tracer) *EmailSender {
	return &EmailSender{tracer}
}

func (e EmailSender) SendVerificationEmail(ctx context.Context, recipient string, verificationId string) {
	senderCtx, span := e.tracer.Start(ctx, "EmailSender.SendVerificationEmail")
	defer span.End()

	content := fmt.Sprintf("Click https://localhost:4200/verification/%s to verify registration.", verificationId)

	e.sendEmail(senderCtx, recipient, content)
}

func (e EmailSender) SendRecoveryEmail(ctx context.Context, recipient string, recoveryId string) {
	senderCtx, span := e.tracer.Start(ctx, "EmailSender.SendRecoveryEmail")
	defer span.End()

	content := fmt.Sprintf("Click https://localhost:4200/recover/%s to recover account.", recoveryId)

	e.sendEmail(senderCtx, recipient, content)
}

func (e EmailSender) SendRegistrationUnsuccessfulEmail(ctx context.Context, recipient string) {
	senderCtx, span := e.tracer.Start(ctx, "EmailSender.SendRegistrationUnsuccessfulEmail")
	defer span.End()

	content := fmt.Sprintf("Your registration was unsuccessful.")

	e.sendEmail(senderCtx, recipient, content)
}

func (e EmailSender) sendEmail(ctx context.Context, recipient string, content string) {
	_, span := e.tracer.Start(ctx, "EmailSender.sendEmail")
	defer span.End()

	from := os.Getenv("SMTP_USER")
	password := os.Getenv("SMTP_PASS")

	to := []string{
		recipient,
	}

	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")

	message := []byte(content)

	auth := smtp.PlainAuth("", from, password, smtpHost)

	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, message)
	if err != nil {
		fmt.Println(err)
		return
	}
}
