package saga

type RegisterUserCommandType int8

const (
	SaveProfile RegisterUserCommandType = iota
	RollbackProfile
	SaveSocialGraph
	RollbackSocialGraph
)

type RegisterUserReplyType int8

const (
	ProfileSuccess RegisterUserReplyType = iota
	ProfileFail
	ProfileRollback
	SocialGraphSuccess
	SocialGraphFail
)
