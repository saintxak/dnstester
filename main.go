package main

import (
	"sync"

	"github.com/spf13/viper"
)

func main() {

	vip := viper.New()
	vip.AddConfigPath("./")
	vip.SetConfigName("cfg")
	vip.MergeInConfig()

	cfg := vip.GetStringMap("config")

	servers := make([]string, 0)
	for _, opt := range cfg["servers"].([]interface{}) {
		servers = append(servers, opt.(string))
	}

	threads := cfg["threads"].(int)
	request_count := cfg["request_count"].(int)
	host := cfg["host"].(string)

	dns := NewDNSR(servers...)
	wg := sync.WaitGroup{}

	for i := 0; i <= threads; i++ {
		wg.Add(1)

		go func() {
			for i := 0; i <= request_count; i++ {
				dns.LookupHost(host)
			}
			wg.Done()
		}()
	}

	go func() {
		collectStats(dns)
	}()

	wg.Wait()
}
