package models

import "go.mongodb.org/mongo-driver/bson/primitive"

// Model JenisUser yang memiliki array ID modul
type JenisUser struct {
	ID            primitive.ObjectID   `json:"_id,omitempty" bson:"_id,omitempty"`
	NmJenisUser   string               `json:"nm_jenis_user,omitempty" bson:"nm_jenis_user,omitempty"`
	ModulIDs      []primitive.ObjectID `json:"modul_ids,omitempty" bson:"modul_ids,omitempty"` // Array dari ID modul yang dimiliki
}
