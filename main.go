package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"passwordgenerator/passwordgenerator"
)

func promptUser(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func promptBool(prompt string) bool {
	response := promptUser(prompt)
	return strings.ToLower(response) == "y"
}

func main() {
	fmt.Println("Welcome to the Password Generator!")

	for {
		seed := promptUser("Enter a seed phrase: ")
		account := promptUser("Enter an account name: ")

		lengthStr := promptUser("Password length (default 12): ")
		length, err := strconv.Atoi(lengthStr)
		if err != nil || length <= 0 {
			length = 12
		}

		options := passwordgenerator.PasswordOptions{
			Length:          length,
			UseUppercase:    promptBool("Use uppercase? (y/n): "),
			UseLowercase:    promptBool("Use lowercase? (y/n): "),
			UseNumbers:      promptBool("Use numbers? (y/n): "),
			UseSpecialChars: promptBool("Use special characters? (y/n): "),
		}

		password, err := passwordgenerator.GeneratePassword(seed, account, options)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		} else {
			fmt.Printf("\nGenerated password: %s\n", password)
		}

		if !promptBool("\nGenerate another password? (y/n): ") {
			break
		}
	}

	fmt.Println("Thank you for using the Password Generator!")
}
