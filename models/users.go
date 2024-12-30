package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type Users struct {
	ID            primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Username      string             `json:"username,omitempty" bson:"username,omitempty"`
	Nm_user       string             `json:"nm_user,omitempty" bson:"nm_user,omitempty"`
	Pass          string             `json:"pass,omitempty" bson:"pass,omitempty"`
	Email         string             `json:"email,omitempty" bson:"email,omitempty"`
	Role_aktif    primitive.ObjectID `json:"role_aktif,omitempty" bson:"role_aktif,omitempty"`
	Created_at    primitive.DateTime `json:"created_at,omitempty" bson:"created_at,omitempty"`
	Jenis_kelamin int8               `json:"jenis_kelamin,omitempty" bson:"jenis_kelamin,omitempty"`
	Photo         string             `json:"photo,omitempty" bson:"photo,omitempty"`
	Phone         string             `json:"phone,omitempty" bson:"phone,omitempty"`
	Token         string             `json:"token,omitempty" bson:"token,omitempty"`
	Id_jenis_user primitive.ObjectID `json:"id_jenis_user,omitempty" bson:"id_jenis_user,omitempty"`
	Pass_2        string             `json:"pass_2,omitempty" bson:"pass_2,omitempty"`
	ModulIDs      []primitive.ObjectID `json:"modul_ids,omitempty" bson:"modul_ids,omitempty"` // Array dari ID modul yang dimiliki
}
