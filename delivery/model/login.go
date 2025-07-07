package model

type GetLoginFlowResponse struct {
	FlowID string `json:"flowId"`
}

type (
	SubmitLoginFlowRequest struct {
		FlowID     string `json:"flowId"`
		Identifier string `json:"identifier"`
		Password   string `json:"password"`
	}

	SubmitLoginFlowResponse struct {
		FullName  string  `json:"fullName"`
		Email     string  `json:"email"`
		StoreID   string  `json:"storeId"`
		SessionID *string `json:"sessionId"`
		ExpireAt  string  `json:"expireAt"`
	}
)
