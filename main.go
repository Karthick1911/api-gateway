package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
	"os"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

func proxy(c *gin.Context) {
	remote, err := url.Parse("http://devapi.zaicrm.com")
	if err != nil {
		panic(err)
	}

	proxy := httputil.NewSingleHostReverseProxy(remote)
	//Define the director func
	//This is a good place to log, for example
	proxy.Director = func(req *http.Request) {
		req.Header = c.Request.Header
		req.Host = remote.Host
		req.URL.Scheme = remote.Scheme
		req.URL.Host = remote.Host
		req.URL.Path = c.Param("proxyPath")
	}

	proxy.ServeHTTP(c.Writer, c.Request)
}

func licenseCheckMiddleware(c *gin.Context) {
	tokenString := c.Request.Header.Get("LicenseKey")
	host := c.Request.Header.Get("Host")

	secret := "111182089311"

	//Validate License Key
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		c.Abort()
		c.JSON(http.StatusUnprocessableEntity, gin.H{"message": "License Key: " + err.Error(), "status": "error", "errorType": "license_error"})
		return
	}

	//Check License Key Validity
	_, ok := token.Claims.(jwt.Claims)
	if !ok && !token.Valid {
		c.Abort()
		c.JSON(http.StatusUnprocessableEntity, gin.H{"message": "License Key: " + err.Error(), "status": "error", "errorType": "license_error"})
		return
	}

	//Get License Key Meta Details
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok && !token.Valid {
		c.Abort()
		c.JSON(http.StatusUnprocessableEntity, gin.H{"message": "License Key: " + err.Error(), "status": "error", "errorType": "license_error"})
		return
	}
	if ok && token.Valid {
		licenseDomain, ok := claims["license_domain"].(string)
		if !ok {
			c.Abort()
			c.JSON(http.StatusUnprocessableEntity, gin.H{"message": "License Key: " + err.Error(), "status": "error", "errorType": "license_error"})
			return
		}
		if licenseDomain != host {
			c.Abort()
			c.JSON(http.StatusUnprocessableEntity, gin.H{"message": "License Key: Invalid License Key", "status": "error", "errorType": "license_error"})
			return
		}
		c.Next()
	}

}

func createLicenseKey() (string, error) {
	var err error
	//Creating Access Token
	//os.Setenv("ACCESS_SECRET", "jdnfksdmfksd") //this should be in an env file
	//os.Getenv("ACCESS_SECRET")
	domain := "test.com"
	secret := "111182089311"

	atClaims := jwt.MapClaims{}
	atClaims["license_domain"] = domain
	atClaims["exp"] = time.Now().Add(time.Minute * 525600).Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	token, err := at.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	return token, nil
}

func main() {
	//fmt.Println(createLicenseKey())

	r := gin.Default()

	//Create a catchall route
	r.Any("/*proxyPath", licenseCheckMiddleware, proxy)

	r.Run(":8080")
}
