package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/fatih/color"
)

var ips []string

func Log(txt string) {
	fmt.Printf("[%s+%s] %s\n", color.BlueString(""), color.WhiteString(""), txt)
}

func CheckMysql(ip string) bool {

	s, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, 3306), 2*time.Second)
	if err != nil {
		return false
	}
	defer s.Close()

	return true
}

func FindX86Link(ip string) (string, error) {
	resp, err := http.Get("https://urlhaus.abuse.ch/downloads/text/")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, ip) && strings.Contains(line, "x86") {
			re := regexp.MustCompile(`(http[s]?:\/\/[^\s]+)`)
			match := re.FindStringSubmatch(line)

			if len(match) > 1 {
				return match[1], nil
			}
		}
	}

	return "", fmt.Errorf(" Scraped ip Without malware link [%s]", ip)
}

func main() {
	Log("Shkid Scanner 6000.")

	resp, err := http.Get("https://urlhaus.abuse.ch/downloads/csv_recent/")
	if err != nil {
		Log(fmt.Sprintf("Error: %v", err))
		return
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()

		if !strings.Contains(strings.ToLower(line), "mirai") {
			continue
		}

		ip := strings.Split(strings.Split(strings.Split(line, ",")[2], "://")[1], "/")[0]

		if strings.Count(ip, ".") != 4 {
			ips, err := net.LookupHost(ip)
			if err != nil {
				continue
			}
			ip = ips[0]
		}

		if contains(ips, ip) {
			continue
		}

		if !CheckMysql(ip) {
			continue
		}

		ips = append(ips, ip)

		x86Link, err := FindX86Link(ip)
		if err != nil {
			Log(fmt.Sprintf("Error: %v", err))
			continue
		}

		Log(fmt.Sprintf("Scraped valid ip [%s] malware link [%s]", ip, x86Link))
	}
}

func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}
