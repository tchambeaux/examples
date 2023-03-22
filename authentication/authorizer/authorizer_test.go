package authorizer_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tchambeaux/examples/authentication/authorizer"
)

var validPublicJWK = map[string]interface{}{
	"kty": "RSA",
	"e":   "AQAB",
	"use": "sig",
	"kid": "VeGdrOow0pVzeeXpuZvXPtE0erL7EuTvU7flCJycxGs",
	"alg": "RS256",
	"n":   "qSNe0lgfhJ5F_u6fXv-i5YfyCDddOzrxH5j1PDHpJWENrPzarKGNqcrjRbiWlQugWEf_Dg7U7MwcS_Cvh1Vk_JDTtHwfDt6ytsGCvVkSAJZ5MlJ8sjwNTKZ5bnstM4tcy7oEdVTctsMcgfGNvLAszjp0ya9bbVWcKbtgtSgFy-qybtMcn5oGdV-HcCV5R1p0GTnzfH2hqeGrZt3_12Sfu3GUNZ0TG4uXmLd1r2b5r3-z25vHz3Xi1Wcr_0Fb9LoKadUP-Dh0LDTBK4X6FZgObq_YwwLsJ7AOKwHwlR5pKC47zrpWfn3WGRvUPSQ3ntZbL1o9zf9oPkK7uy-GvSQZ7Q",
}

var notJsonPublicJWK = map[string]interface{}{
	"kty":  "RSA",
	"e":    "AQAB",
	"use":  "sig",
	"kid":  "VeGdrOow0pVzeeXpuZvXPtE0erL7EuTvU7flCJycxGs",
	"alg":  "RS256",
	"n":    "qSNe0lgfhJ5F_u6fXv-i5YfyCDddOzrxH5j1PDHpJWENrPzarKGNqcrjRbiWlQugWEf_Dg7U7MwcS_Cvh1Vk_JDTtHwfDt6ytsGCvVkSAJZ5MlJ8sjwNTKZ5bnstM4tcy7oEdVTctsMcgfGNvLAszjp0ya9bbVWcKbtgtSgFy-qybtMcn5oGdV-HcCV5R1p0GTnzfH2hqeGrZt3_12Sfu3GUNZ0TG4uXmLd1r2b5r3-z25vHz3Xi1Wcr_0Fb9LoKadUP-Dh0LDTBK4X6FZgObq_YwwLsJ7AOKwHwlR5pKC47zrpWfn3WGRvUPSQ3ntZbL1o9zf9oPkK7uy-GvSQZ7Q",
	"func": func() {},
}

var wrongAlgoPublicJWK = map[string]interface{}{
	"kty": "HSA",
	"e":   "AQAB",
	"use": "sig",
	"kid": "VeGdrOow0pVzeeXpuZvXPtE0erL7EuTvU7flCJycxGs",
	"alg": "RS256",
	"n":   "qSNe0lgfhJ5F_u6fXv-i5YfyCDddOzrxH5j1PDHpJWENrPzarKGNqcrjRbiWlQugWEf_Dg7U7MwcS_Cvh1Vk_JDTtHwfDt6ytsGCvVkSAJZ5MlJ8sjwNTKZ5bnstM4tcy7oEdVTctsMcgfGNvLAszjp0ya9bbVWcKbtgtSgFy-qybtMcn5oGdV-HcCV5R1p0GTnzfH2hqeGrZt3_12Sfu3GUNZ0TG4uXmLd1r2b5r3-z25vHz3Xi1Wcr_0Fb9LoKadUP-Dh0LDTBK4X6FZgObq_YwwLsJ7AOKwHwlR5pKC47zrpWfn3WGRvUPSQ3ntZbL1o9zf9oPkK7uy-GvSQZ7Q",
}

var wrongNPublicJWK = map[string]interface{}{
	"kty": "RSA",
	"e":   "AQAB",
	"use": "sig",
	"kid": "VeGdrOow0pVzeeXpuZvXPtE0erL7EuTvU7flCJycxGs",
	"alg": "RS256",
	"n":   "falseN",
}

const validToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IlZlR2RyT293MHBWemVlWHB1WnZYUHRFMGVyTDdFdVR2VTdmbENKeWN4R3MifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0Ijo5OTk5OTk5OTksImV4cCI6OTk5OTk5OTk5OTl9.hhnDS0t6jsMwZiXd360NFT-qAt01vmnXuBKK82SqoPLdyrVReGD52n6XzsjSg6ZVrVw2CX-6qCWSkkJbPyOMGrT2aKuAmE2-NPGaKwtIbPmHqbrZ3kSM8cueA2S7fhySwdAPEW2z6w367adiwHNDnHXyrFfLOvBMbSzBbv4JVk1BJkzbAGCYHvxDZ1OTTwk5bbt_bmQOqEptuDdi9sMr06auOD7q1xITyiNFehIxLfisLmMSnfgq9Ot1OBCRt0koGcloZB67QOtBiSm3bACpc-Wup1t_1BDW40yELFpvD7i61V4iaXCJ5Sa_hTNBFCb5yIxvFiJE4onT9wTxvolI7w"
const forgedToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IlZlR2RyT293MHBWemVlWHB1WnZYUHRFMGVyTDdFdVR2VTdmbENKeWN4R3MifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0Ijo5OTk5OTk5OTk5OTl9.UwZfqCUEHtFEX77j2CUWASeE-VmKT0aigui9IGXwRV1AF49vq8ODwLsXMJEKeCZ2KoEtsurKqYv1GXaE6h1b5l-PMDZc-LmVXJeunhDZsbWmRc_OfmzSzVDH3b33jfsRQLKBnRIUO5tLNXmbjsrtD5V0sQrmLxXz5a5ufCNSm63DXhJsHcCPiazurTMTDOpLvFjUvaQ_IKT-IBh-M1as_kmstRYIXI6lWSeUhlEro6NbcM8UGCzmt58ZLtFAqa9kvJ5vM2LkHRZ-QrHvncKjNDcz6yw0rQln4hIVANtRJ1v2km3NW3hBQY--XWZQfUwKS16DWeVq0aMojZH9Ce_IUQF"
const missingKidToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0Ijo5OTk5OTk5OTk5OTksImtpZCI6IlZlR2RyT293MHBWemVlWHB1WnZYUHRFMGVyTDdFdVR2VTdmbENKeWN4R3MifQ.GYyz2qy5Uhqs9ZP-pIu0aXC-g_syhWgUMkzdoKB_DQ55ahpQ7tX5ddZJKTvi5NivXd2N5uDqtXqbkIMqiOtJsjBH-MEuKATME3F8WxD4PMDPf6F6e-Nuo0_LXEnJcVNikOAN426ihj72Ik-oCyUm2n46irBvYa6YPzTCXW1d5Mbd7TTpk1PFt5DuogV6XwDOMN82Izx-HiXV_ywReKYGvO_IxuJZ-pWKi680B-jBi5ndtLD2g3QHTAabgQ5j0aeiQBwAZidQRHnoOLQ2HrKQKsWn8HqrWGJFUSG-W4doi6b7ebPxswtksYNq66_pNqYgzub1foSHk_atZCrnVOjpew"
const expiredToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IlZlR2RyT293MHBWemVlWHB1WnZYUHRFMGVyTDdFdVR2VTdmbENKeWN4R3MifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0Ijo5OTk5OTk5OTksImV4cCI6LTk5OTk5OTk5OTk5fQ.W1tcpkBXXQEI8qs7PthWZuq2K5rjx7UXi5_mAKPnHHZYuEVwKT3bw2oSW9iOnCetGxRuJzw0TgEAEUGesCVn1CNrFRBxQKSx3FHwMq0_F6-0kZ2mK6vuk--TrqMCeZNXT_Knq-J97wRQom8fGBNCxB7CCfIUNrge7GJlqaUWg8_i9BOFBfEn_WWaIpXW1ZuBH0OQ7X8pnWGblplMHNcvdxXVwLE7jkbSuLbOOsg33et5GmN0BGfpKB4ghNDRS0iho79ZJEIPFiNGutNCJpN0DJvrMYtoxya9XctVbQ5gQ9GqySWWCXvlBuQ7oUUHi1eLaA7vyWqdim2zgH4RYOfu9w"
const wrongAlgToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IlZlR2RyT293MHBWemVlWHB1WnZYUHRFMGVyTDdFdVR2VTdmbENKeWN4R3MifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0Ijo5OTk5OTk5OTksImV4cCI6OTk5OTk5OTk5OTl9.UksTgr2DScvkMgwNk1JFz35UKbp495cCD9mD0xke89Q"

type inputVerifyToken struct {
	Token string
	Keys  []map[string]interface{}
}

type outputVerifyToken struct {
	Err error
}

type testerVerifyToken struct {
	Input  inputVerifyToken
	Output outputVerifyToken
}

var testVerifyToken = map[string]testerVerifyToken{
	"valid": {
		Input: inputVerifyToken{
			Token: validToken,
			Keys: []map[string]interface{}{
				validPublicJWK,
			},
		},
		Output: outputVerifyToken{
			Err: nil,
		},
	},
	"missing kid": {
		Input: inputVerifyToken{
			Token: missingKidToken,
			Keys: []map[string]interface{}{
				validPublicJWK,
			},
		},
		Output: outputVerifyToken{
			Err: errors.New("test"),
		},
	},
	"wrong alg token": {
		Input: inputVerifyToken{
			Token: wrongAlgToken,
			Keys: []map[string]interface{}{
				validPublicJWK,
			},
		},
		Output: outputVerifyToken{
			Err: errors.New("test"),
		},
	},
	"forged token": {
		Input: inputVerifyToken{
			Token: forgedToken,
			Keys: []map[string]interface{}{
				validPublicJWK,
			},
		},
		Output: outputVerifyToken{
			Err: errors.New("test"),
		},
	},
	"expired token": {
		Input: inputVerifyToken{
			Token: expiredToken,
			Keys: []map[string]interface{}{
				validPublicJWK,
			},
		},
		Output: outputVerifyToken{
			Err: errors.New("test"),
		},
	},
	"not json key": {
		Input: inputVerifyToken{
			Token: validToken,
			Keys: []map[string]interface{}{
				notJsonPublicJWK,
			},
		},
		Output: outputVerifyToken{
			Err: errors.New("test"),
		},
	},
	"wrong algo key": {
		Input: inputVerifyToken{
			Token: validToken,
			Keys: []map[string]interface{}{
				wrongAlgoPublicJWK,
			},
		},
		Output: outputVerifyToken{
			Err: errors.New("test"),
		},
	},
	"wrong n": {
		Input: inputVerifyToken{
			Token: validToken,
			Keys: []map[string]interface{}{
				wrongNPublicJWK,
			},
		},
		Output: outputVerifyToken{
			Err: errors.New("test"),
		},
	},
}

func TestVerifyToken(t *testing.T) {
	for k, v := range testVerifyToken {
		t.Run(k, func(t *testing.T) {
			err := authorizer.VerifyToken(v.Input.Token, v.Input.Keys)
			if v.Output.Err != nil {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}

		})
	}
}

type inputAppendKeysFromUrl struct {
	Ctx      context.Context
	Client   http.Client
	Handler1 http.HandlerFunc
	Handler2 http.HandlerFunc
}

type outputAppendKeysFromUrl struct {
	Result []map[string]interface{}
	Err    error
}

type testerAppendKeysFromUrl struct {
	Input  inputAppendKeysFromUrl
	Output outputAppendKeysFromUrl
}

var suiteAppendKeysFromUrl = map[string]testerAppendKeysFromUrl{
	"ok": {
		Input: inputAppendKeysFromUrl{
			Ctx:    context.Background(),
			Client: http.Client{},
			Handler1: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`{"keys":[{"kid":"test","e":"AQAB","n":"test","alg":"RS256","kty":"RSA","use":"sig"},{"kid":"othertest","e":"AQAB","n":"othertest","alg":"RS256","kty":"RSA","use":"sig"}]}`))
			},
			Handler2: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`{"keys":[{"kid":"otherservertest","e":"AQAB","n":"otherservertest","alg":"RS256","kty":"RSA","use":"sig"}]}`))
			},
		},
		Output: outputAppendKeysFromUrl{
			Result: []map[string]interface{}{
				{
					"kid": "test",
					"e":   "AQAB",
					"n":   "test",
					"alg": "RS256",
					"kty": "RSA",
					"use": "sig",
				},
				{
					"kid": "othertest",
					"e":   "AQAB",
					"n":   "othertest",
					"alg": "RS256",
					"kty": "RSA",
					"use": "sig",
				},
				{
					"kid": "otherservertest",
					"e":   "AQAB",
					"n":   "otherservertest",
					"alg": "RS256",
					"kty": "RSA",
					"use": "sig",
				},
			},
		},
	},
	"json error": {
		Input: inputAppendKeysFromUrl{
			Ctx:    context.Background(),
			Client: http.Client{},
			Handler1: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`notjson`))
			},
			Handler2: func(w http.ResponseWriter, r *http.Request) {
				// Not an array of keys
				w.Write([]byte(`notjson`))
			},
		},
		Output: outputAppendKeysFromUrl{
			Result: nil,
			Err:    errors.New("test"),
		},
	},
	"keys not an array error": {
		Input: inputAppendKeysFromUrl{
			Ctx:    context.Background(),
			Client: http.Client{},
			Handler1: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(`{"keys":[{"kid":"test","e":"AQAB","n":"test","alg":"RS256","kty":"RSA","use":"sig"},{"kid":"othertest","e":"AQAB","n":"othertest","alg":"RS256","kty":"RSA","use":"sig"}]}`))
			},
			Handler2: func(w http.ResponseWriter, r *http.Request) {
				// Not an array of keys
				w.Write([]byte(`{"keys":{"kid":"otherservertest","e":"AQAB","n":"otherservertest","alg":"RS256","kty":"RSA","use":"sig"}}`))
			},
		},
		Output: outputAppendKeysFromUrl{
			Result: nil,
			Err:    errors.New("test"),
		},
	},
}

func TestAppendKeysFromUrl(t *testing.T) {
	for k, v := range suiteAppendKeysFromUrl {
		t.Run(k, func(tst *testing.T) {
			srv1 := httptest.NewServer(v.Input.Handler1)
			defer srv1.Close()
			srv2 := httptest.NewServer(v.Input.Handler2)
			defer srv2.Close()
			out, err := authorizer.AppendKeysFromUrl(v.Input.Ctx, v.Input.Client, []string{srv1.URL, srv2.URL})
			if v.Output.Err != nil {
				assert.Error(tst, err)
			} else {
				assert.Nil(tst, err)
				assert.Equal(tst, v.Output.Result, out)
			}
		})
	}
}
