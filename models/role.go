package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type Role struct {
	ID   primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Nm_role string          `json:"nm_role,omitempty" bson:"nm_role,omitempty"`
	Created_at primitive.DateTime `json:"created_at,omitempty" bson:"created_at,omitempty"`
	Created_by int8 `json:"created_by,omitempty" bson:"created_by,omitempty"`
	Updated_at primitive.DateTime `json:"updated_at,omitempty" bson:"updated_at,omitempty"`
	Updated_by int8 `json:"updated_by,omitempty" bson:"updated_by,omitempty"`
}
