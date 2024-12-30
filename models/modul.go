package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type Modul struct {
	ID   primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Nm_modul string          `json:"nm_modul,omitempty" bson:"nm_modul,omitempty"`
	Ket_modul string    	`json:"ket_modul,omitempty" bson:"ket_modul,omitempty"`
	Kategori_id primitive.ObjectID `json:"kategori_id,omitempty" bson:"kategori_id,omitempty"`
	Is_aktif int8			`json:"is_aktif,omitempty" bson:"is_aktif,omitempty"`
	Alamat string 			`json:"alamat,omitempty" bson:"alamat,omitempty"`
	Urutan int8 			`json:"urutan,omitempty" bson:"urutan,omitempty"`
	Gbr_icon string 		`json:"gbr_icon,omitempty" bson:"gbr_icon,omitempty"`
	Created_at primitive.DateTime `json:"created_at,omitempty" bson:"created_at,omitempty"`
	Created_by primitive.ObjectID 	`json:"created_by,omitempty" bson:"created_by,omitempty"`
	Updated_at primitive.DateTime `json:"updated_at,omitempty" bson:"updated_at,omitempty"`
	Updated_by primitive.ObjectID  	`json:"updated_by,omitempty" bson:"updated_by,omitempty"`
	Icon string 	`json:"icon,omitempty" bson:"icon,omitempty"`
}

