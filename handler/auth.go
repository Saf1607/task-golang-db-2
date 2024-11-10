package handler

import (
	"errors"
	"fmt"
	"go-db-new/model"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type AuthInterface interface {
	Login(*gin.Context)
	Upsert(*gin.Context)
	ChangePassword(c *gin.Context)
}

type authImplement struct {
	db         *gorm.DB
	signingKey []byte
}

func NewAuth(db *gorm.DB, signingKey []byte) AuthInterface {
	return &authImplement{
		db,
		signingKey,
	}
}

type authLoginPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (a *authImplement) Login(c *gin.Context) {
	payload := authLoginPayload{}

	// parsing JSON payload to struct model
	err := c.BindJSON(&payload)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		return
	}

	// Validate username to get auth data
	auth := model.Auth{}
	if err := a.db.Where("username = ?",
		payload.Username).
		First(&auth).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "username salah",
			})
			return
		}

		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	log.Printf("Attempting login for username: %s", payload.Username)
	log.Printf("Stored hashed password: %s", auth.Password)
	log.Printf("Password to verify: %s", payload.Password)
	// Validate password
	if err := bcrypt.CompareHashAndPassword([]byte(auth.Password), []byte(payload.Password)); err != nil {
		log.Printf("Password comparison failed: %v", err)
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "password salah",
		})
		return
	}

	// Login is valid
	token, err := a.createJWT(&auth)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": err,
		})
		return
	}

	// c.SetSameSite(http.SameSiteLaxMode) // Set SameSite attribute (for cross-origin requests)
	// c.SetCookie("auth_token", token, 3600*72, "/", "", false, true)

	// Success response
	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("%v Login Sukses", payload.Username),
		"data":    token,
	})
}

type authUpsertPayload struct {
	AccountID int64  `json:"account_id"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Hashed    bool   `json:"-"`
}

func (a *authImplement) Upsert(c *gin.Context) {
	// Check if ChangePassword provided upsertPayload in the context
	value, exists := c.Get("upsertPayload")

	var payload authUpsertPayload
	if exists {
		// If upsertPayload exists in the context, use it (from ChangePassword)
		upsertPayload, ok := value.(authUpsertPayload)
		if !ok {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid upsert payload format"})
			return
		}
		payload = upsertPayload
	} else {
		// If no upsertPayload, bind JSON from request to support creating or updating auth login directly
		err := c.BindJSON(&payload)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
			return
		}
	}

	// Only hash the password if it hasn't been hashed yet
	if !payload.Hashed {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
		log.Printf("Saving hashed password: %s for username: %s", payload.Password, payload.Username)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}
		payload.Password = string(hashedPassword)
		payload.Hashed = true // Mark it as hashed
	}

	log.Printf("Saving hashed password: %s", payload.Password)

	// Check if AccountID is valid
	var account model.Account
	if err := a.db.First(&account, payload.AccountID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Account not found"})
			return
		}
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Database error", "details": err.Error()})
		return
	}

	// Prepare new auth data with payload
	auth := model.Auth{
		AccountID: payload.AccountID,
		Username:  payload.Username,
		Password:  payload.Password, // This will be the hashed password
	}

	// Upsert auth data (Insert or Update if already exists)
	result := a.db.Clauses(
		clause.OnConflict{
			DoUpdates: clause.AssignmentColumns([]string{"username", "password"}),
			Columns:   []clause.Column{{Name: "account_id"}},
		}).Create(&auth)
	if result.Error != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to upsert auth", "details": result.Error.Error()})
		return
	}

	// Success response
	c.JSON(http.StatusOK, gin.H{
		"message": "Upsert operation successful",
		"data":    payload.Username,
	})
}

// ChangePassword function
func (a *authImplement) ChangePassword(c *gin.Context) {
	var changePasswordPayload struct {
		NewPassword        string `json:"new_password"`
		ConfirmNewPassword string `json:"confirm_new_password"`
	}

	// Bind and validate the payload
	if err := c.ShouldBindJSON(&changePasswordPayload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	if changePasswordPayload.NewPassword != changePasswordPayload.ConfirmNewPassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Passwords do not match"})
		return
	}

	// Retrieve claims from token for account_id and username
	claims, exists := c.Get("claims")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	userClaims := claims.(jwt.MapClaims)
	accountID := int64(userClaims["account_id"].(float64))
	username := userClaims["username"].(string)

	// Validate that the user exists in the database
	var auth model.Auth
	if err := a.db.Where("account_id = ? AND username = ?", accountID, username).First(&auth).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// Hash the new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(changePasswordPayload.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	log.Printf("Saving hashed password: %s", changePasswordPayload.NewPassword)

	// Set up upsertPayload with the hashed password
	upsertPayload := authUpsertPayload{
		AccountID: accountID,
		Username:  username,
		Password:  string(hashedPassword), // Use the hashed password here
		Hashed:    true,                   // Mark the password as hashed
	}

	// Pass upsertPayload to Upsert via context
	c.Set("upsertPayload", upsertPayload)
	a.Upsert(c)
}

func (a *authImplement) createJWT(auth *model.Auth) (string, error) {
	// Create the jwt token signer
	token := jwt.New(jwt.SigningMethodHS256)

	// Add claims data or additional data (avoid to put secret information in the payload or header elements)
	claims := token.Claims.(jwt.MapClaims)
	claims["auth_id"] = auth.AuthID
	claims["account_id"] = auth.AccountID
	claims["username"] = auth.Username
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix() // Token expires in 72 hours

	// Encode
	tokenString, err := token.SignedString(a.signingKey)
	if err != nil {
		return "", err
	}

	// Return the token
	return tokenString, nil
}
