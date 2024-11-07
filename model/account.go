package model

type Account struct {
	AccountID int64  `json:"account_id" gorm:"primaryKey;autoIncrement;<-:false"`
	Nama      string `json:"nama"`
	Balance   int64  `json:"balance"`
}

// func (Account) TableName() string {
// 	return "accounts"
// }
