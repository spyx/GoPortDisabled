package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"syscall"

	"github.com/networklore/netrasp/pkg/netrasp"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	username, password, _ := credentials()
	fmt.Println()
	fmt.Println("Start scanning")

	file, err := os.Open("switches")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	var wg sync.WaitGroup
	ips := make(chan string)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for x := range ips {
				device, err := netrasp.New(x,
					netrasp.WithUsernamePassword(username, password),
					netrasp.WithDriver("ios"), netrasp.WithInsecureIgnoreHostKey(), netrasp.WithSSHKeyExchange("diffie-hellman-group1-sha1"), netrasp.WithSSHCipher("aes128-cbc"),
				)
				//wg.Done()

				if err != nil {
					log.Fatalf("unable to initialize device: %v", err)
				}
				err = device.Dial(context.Background())
				if err != nil {
					fmt.Printf("unable connect to %s : %s\n", x, err)
					continue

				}

				output, err := device.Run(context.Background(), "sh interfaces status err-disabled")
				if err != nil {
					log.Fatalf("unable to run command: %v", err)
				}
				device.Close(context.Background())
				if output != "\n" && output != "" {
					fmt.Printf("IP: %s -> %s\n", x, output)
				}

			}

		}()

	}

	for scanner.Scan() {
		//fmt.Println(scanner.Text())
		ip := scanner.Text()
		ips <- ip

	}
	close(ips)
	wg.Wait()
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	//wg.Wait()
	fmt.Println("Scanning completed")
}

func credentials() (string, string, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter Username: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		return "", "", err
	}

	fmt.Print("Enter Password: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", "", err
	}

	password := string(bytePassword)
	return strings.TrimSpace(username), strings.TrimSpace(password), nil
}
