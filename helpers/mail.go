package helpers

import "fmt"

func SendEmailWarning(email string, newIP string) {
	fmt.Printf("Подозрительная активность пользователя %s. New IP: %s\n", email, newIP)
}
