package models

import (
	logging "github.com/golang/glog"
)

type SessionType struct {
	Id          uint   `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Duration    uint   `json:"duration`
}

type Session struct {
	Id          uint          `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Duration    uint          `json:"duration`
	Sessions    []SessionType `json:"associated_session_types"`
}

func (session_type *SessionType) Validate() (map[string]interface{}, bool) {
	logging.Infof("Validating session type %v", session_type)
	return nil, false
}

func (session *Session) Validate() (map[string]interface{}, bool) {
	logging.Infof("Validating session %v", session)
	return nil, false
}
