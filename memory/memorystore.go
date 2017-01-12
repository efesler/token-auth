package memstore

import (
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"github.com/freehaha/token-auth"
	"time"
	"github.com/golang/glog"
	"fmt"
)

type MemoryTokenStore struct {
	tokens   map[string]*MemoryToken
	salt     string
}

type MemoryToken struct {
	ExpireAt time.Time
	Token    string
	Id       string
}

func (t *MemoryToken) IsExpired() bool {
	return time.Now().After(t.ExpireAt)
}

func (t *MemoryToken) String() string {
	return t.Token
}

/* lookup 'exp' or 'id' */
func (t *MemoryToken) Claims(key string) interface{} {
	switch key {
	case "exp":
		return t.ExpireAt
	case "id":
		return t.Id
	default:
		return nil
	}
}

func (s *MemoryTokenStore) generateToken(id string) []byte {
	hash := sha1.New()
	now := time.Now()
	timeStr := now.Format(time.ANSIC)
	hash.Write([]byte(timeStr))
	hash.Write([]byte(id))
	hash.Write([]byte("salt"))
	return hash.Sum(nil)
}

/* returns a new token with specific id */
func (s *MemoryTokenStore) NewToken(id interface{}) *MemoryToken {
	return s.NewTokenWithDuration(id, time.Minute * 30)
}

func (s *MemoryTokenStore) NewTokenWithDuration(id interface{}, duration time.Duration) *MemoryToken  {
	strId := id.(string)
	bToken := s.generateToken(strId)
	strToken := base64.URLEncoding.EncodeToString(bToken)
	t := &MemoryToken{
		ExpireAt: time.Now().Add(duration),
		Token:    strToken,
		Id:       strId,
	}

	delete(s.tokens, strToken)

	s.tokens[strToken] = t
	return t
}

/* Create a new memory store */
func New(salt string) *MemoryTokenStore {
	return &MemoryTokenStore{
		salt:     salt,
		tokens:   make(map[string]*MemoryToken),
	}

}

func (s *MemoryTokenStore) CheckToken(strToken string) (tauth.Token, error) {
	t, ok := s.tokens[strToken]
	if !ok {
		return nil, errors.New("Failed to authenticate")
	}
	if t.ExpireAt.Before(time.Now()) {
		delete(s.tokens, strToken)
		return nil, errors.New(fmt.Sprintf("Token expired at %v", t.ExpireAt))
	}
	return t, nil
}

func (s *MemoryTokenStore) RefreshToken(strToken string) error {
	return s.RefreshTokenForDuration(strToken, time.Minute * 30)
}

func (s *MemoryTokenStore) RefreshTokenForDuration(strToken string, duration time.Duration) error  {
	t, ok := s.tokens[strToken]
	if !ok {
		return errors.New("Failed to authenticate")
	}
	t.ExpireAt = time.Now().Add(duration)
	glog.Infof("token will now expire at %v", t.ExpireAt)
	return nil
}

func (s *MemoryTokenStore) RemoveToken(strToken string) {
	glog.Infof("Remove token: %v", strToken)
	delete(s.tokens, strToken)
}
