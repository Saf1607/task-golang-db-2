package handler

import (
	"go-db-new/model"
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type AccountInterface interface {
	Create(*gin.Context)
	Read(*gin.Context)
	Update(*gin.Context)
	Delete(*gin.Context)
	List(*gin.Context)
	Balance(*gin.Context)
	TopUp(*gin.Context)

	My(*gin.Context)
}

type accountImplement struct {
	db *gorm.DB
}

func NewAccount(db *gorm.DB) AccountInterface {
	return &accountImplement{
		db: db,
	}
}

func (a *accountImplement) Create(c *gin.Context) {
	payload := model.Account{}

	// bind JSON Request to payload
	err := c.BindJSON(&payload)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		return
	}

	// Create data
	result := a.db.Create(&payload)
	if result.Error != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": result.Error.Error(),
		})
		return
	}

	// Success response
	c.JSON(http.StatusOK, gin.H{
		"message": "Create success",
		"data":    payload,
	})
}

func (a *accountImplement) Read(c *gin.Context) {
	var account model.Account

	// get id from url account/read/5, 5 will be the id
	id := c.Param("id")

	// Find first data based on id and put to account model
	if err := a.db.First(&account, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"error": "Not found",
			})
			return
		}

		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Success response
	c.JSON(http.StatusOK, gin.H{
		"data": account,
	})
}

func (a *accountImplement) Update(c *gin.Context) {
	payload := model.Account{}

	// bind JSON Request to payload
	err := c.BindJSON(&payload)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		return
	}

	// get id from url account/update/5, 5 will be the id
	id := c.Param("id")

	// Find first data based on id and put to account model
	account := model.Account{}
	result := a.db.First(&account, "account_id = ?", id)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"error": "Not found",
			})
			return
		}
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": result.Error.Error(),
		})
		return
	}

	// Update data
	account.Nama = payload.Nama
	a.db.Save(account)

	// Success response
	c.JSON(http.StatusOK, gin.H{
		"message": "Update success",
	})
}

func (a *accountImplement) Delete(c *gin.Context) {
	// get id from url account/delete/5, 5 will be the id
	id := c.Param("id")

	// Find first data based on id and delete it
	if err := a.db.Where("account_id = ?", id).Delete(&model.Account{}).Error; err != nil {
		// No data found and deleted
		if err == gorm.ErrRecordNotFound {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"error": "Not found",
			})
			return
		}
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Success response
	c.JSON(http.StatusOK, gin.H{
		"message": "Delete success",
		"data": map[string]string{
			"account_id": id,
		},
	})
}

func (a *accountImplement) List(c *gin.Context) {
	// Prepare empty result
	var accounts []model.Account

	// Find and get all accounts data and put to &accounts
	if err := a.db.Find(&accounts).Error; err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Success response
	c.JSON(http.StatusOK, gin.H{
		"data": accounts,
	})
}

func (a *accountImplement) TopUp(c *gin.Context) {
	// Struct untuk payload input
	var payload struct {
		AccountID int64 `json:"account_id"`
		Amount    int64 `json:"amount"`
	}

	// Bind input JSON ke payload
	if err := c.BindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Cari akun berdasarkan account_id
	var account model.Account
	if err := a.db.First(&account, "account_id = ?", payload.AccountID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Account not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Tambahkan saldo
	account.Balance += payload.Amount
	if err := a.db.Save(&account).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update balance"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Top up successful", "balance": account.Balance})
}

func (a *accountImplement) Balance(c *gin.Context) {
	// Dapatkan account_id dari middleware auth
	accountID := c.GetInt64("account_id")

	// Ambil data akun berdasarkan account_id
	var account model.Account
	if err := a.db.First(&account, "account_id = ?", accountID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Account not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Kembalikan saldo saat ini
	c.JSON(http.StatusOK, gin.H{"balance": account.Balance})
}

func (a *accountImplement) My(c *gin.Context) {
	var account model.Account
	// get account_id from middleware auth
	accountID := c.GetInt64("account_id")

	// Find first data based on account_id given
	if err := a.db.First(&account, accountID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"error": "Not found",
			})
			return
		}

		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	// Success response
	c.JSON(http.StatusOK, gin.H{
		"data": account,
	})
}