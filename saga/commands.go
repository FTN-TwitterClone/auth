package saga

const (
	REGISTER_COMMAND = "register.reply"
	REGISTER_REPLY   = "register.command"
)

type RegisterUserCommandType int8

const (
	SaveProfile RegisterUserCommandType = iota
	RollbackProfile
	SaveSocialGraph
	RollbackSocialGraph
	ConfirmAuth
	RollbackAuth
)

type RegisterUserReplyType int8

const (
	ProfileSuccess RegisterUserReplyType = iota
	ProfileFail
	ProfileRollback
	SocialGraphSuccess
	SocialGraphFail
)

// User Combined data of business and ordinary user.
// Combining is the simplest solution, since Go is statically typed.
type NewUser struct {
	Username    string
	Email       string
	FirstName   string
	LastName    string
	Town        string
	Gender      string
	Website     string
	CompanyName string
	Private     bool
	Role        string
}

type RegisterUserCommand struct {
	Command RegisterUserCommandType
	User    NewUser
}

type RegisterUserReply struct {
	Reply RegisterUserReplyType
	User  NewUser
}
