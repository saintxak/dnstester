package main

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type dnsServer struct {
	addr               string
	maxRequestTime     time.Duration
	minRequestTime     time.Duration
	lastRequestTime    time.Duration
	averageRequestTime time.Duration
	sumReqeustTime     time.Duration
	requestCount       int
	timeoutCount       int
	nxCount            int
	okCount            int
	quality            float64
	skip               bool
	skipDelay          time.Time
	mtx                *sync.Mutex
	pool               *dnsConnectionPool
}

type dnsConnection struct {
	conn     *dns.Conn
	isLocked int32
	isClosed bool
}

type dnsConnectionPool struct {
	pool []*dnsConnection
	size int
	host string
	mtx  *sync.Mutex
}

type dnsResolver struct {
	servers    []*dnsServer
	retryTimes int
	listLocker int32
}

//NewDNSR create new dns resolver with support many servers
func NewDNSR(dnsServers ...string) *dnsResolver {
	dnsList := make([]*dnsServer, 0)

	for _, opt := range dnsServers {
		server := NewDNSServer(opt)
		dnsList = append(dnsList, server)
	}

	dnsResolver := new(dnsResolver)
	dnsResolver.servers = dnsList

	dnsResolver.retryTimes = 200

	return dnsResolver
}

func (r *dnsResolver) LookupHost(host string) ([]net.IP, error) {
	list, err := r.lookupByStrategyServer(r.createDNSMessage(host), r.retryTimes)
	return list, err
}

func (r *dnsResolver) GetRetryTimes() int {
	return r.retryTimes
}

func (r *dnsResolver) SetRetryTimes(rt int) {
	r.retryTimes = rt
}

func (r *dnsResolver) lookupByStrategyServer(msg *dns.Msg, triesLeft int) ([]net.IP, error) {
	for atomic.LoadInt32(&r.listLocker) == 1 {
		time.Sleep(time.Millisecond * 100)
	}

	return r.lookupRoundRobinServer(msg, 0)
}

var roundIndex int = 0

func (r *dnsResolver) lookupRoundRobinServer(msg *dns.Msg, triesLeft int) ([]net.IP, error) {
	server := r.servers[roundIndex]

	roundIndex++
	if roundIndex == len(r.servers) {
		roundIndex = 0
	}

	return r.lookupHost(msg, server, triesLeft)
}

func (r *dnsResolver) lookupHost(msg *dns.Msg, server *dnsServer, triesLeft int) ([]net.IP, error) {
	if msg == nil {
		return nil, errors.New("Invalid msg for dns request")
	}

	dnsClient := dns.Client{
		Net:         "udp",
		DialTimeout: time.Second * 2,
		Timeout:     time.Second * 2,
	}

	start := time.Now()

	conn := server.pool.GetConnection()
	in, _, err := dnsClient.ExchangeWithConn(msg, conn.Unwrap().(*dns.Conn))
	server.pool.FreeConnection(conn)

	server.lock()
	server.setLastRequestTime(time.Since(start))

	result := []net.IP{}

	if err != nil {
		if (strings.Contains(err.Error(), "i/o timeout") || strings.Contains(err.Error(), "connection refused")) && triesLeft > 0 {
			triesLeft--
			server.timeoutCount++
			server.unlock()
			return r.lookupByStrategyServer(msg, triesLeft)
		} else if strings.Contains(err.Error(), "i/o timeout") || strings.Contains(err.Error(), "connection refused") {
			server.timeoutCount++
			server.unlock()

			return result, err
		}

		server.nxCount++
		server.unlock()

		return result, err
	}

	if in != nil && in.Rcode != dns.RcodeSuccess {
		server.nxCount++

		if in.Rcode == dns.RcodeNameError && triesLeft > 0 {
			triesLeft--
			server.unlock()
			return r.lookupByStrategyServer(msg, triesLeft)
		}

		server.unlock()

		err := &net.DNSError{Err: dns.RcodeToString[in.Rcode], Server: server.addr}

		return result, err
	}

	for _, record := range in.Answer {
		if t, ok := record.(*dns.A); ok {
			result = append(result, t.A)
		}
	}

	server.okCount++

	server.unlock()
	return result, err
}

func (r *dnsResolver) createDNSMessage(host string) *dns.Msg {
	m1 := new(dns.Msg)
	m1.Id = dns.Id()
	m1.RecursionDesired = true
	m1.Question = make([]dns.Question, 1)
	m1.Question[0] = dns.Question{dns.Fqdn(host), dns.TypeA, dns.ClassINET}

	return m1
}

func NewDNSServer(address string) *dnsServer {
	server := &dnsServer{
		mtx:  &sync.Mutex{},
		addr: address,
	}

	poolSize := 10

	pool, err := NewDNSConnectionPool(poolSize, address)
	if err != nil {
		panic(err)
	}

	server.pool = pool

	return server
}

func (server *dnsServer) GetAddress() string {
	return server.addr
}

func (server *dnsServer) GetLastRequestTime() time.Duration {
	return server.lastRequestTime
}

func (server *dnsServer) GetMaxRequestTime() time.Duration {
	return server.maxRequestTime
}

func (server *dnsServer) GetMinRequestTime() time.Duration {
	return server.minRequestTime
}

func (server *dnsServer) GetAverageRequestTime() time.Duration {
	return server.averageRequestTime
}

func (server *dnsServer) GetQuality() float64 {
	return server.quality
}

func (server *dnsServer) GetRequestCount() int {
	return server.requestCount
}

func (server *dnsServer) IsSkipped() bool {
	return server.skip
}

func (server *dnsServer) GetSkipDelay() time.Time {
	return server.skipDelay
}

func (server *dnsServer) GetTimeoutCount() int {
	return server.timeoutCount
}

func (server *dnsServer) GetNXCount() int {
	return server.nxCount
}

func (server *dnsServer) GetOkCount() int {
	return server.okCount
}

func (server *dnsServer) setLastRequestTime(t time.Duration) {
	server.lastRequestTime = t
	if t > server.maxRequestTime {
		server.maxRequestTime = t
	}

	if server.minRequestTime == 0 {
		server.minRequestTime = t
	}

	if t < server.minRequestTime {
		server.minRequestTime = t
	}

	server.requestCount++
	server.sumReqeustTime += t
	server.averageRequestTime = time.Duration((int64(server.sumReqeustTime) / int64(server.requestCount)))
}

func (server *dnsServer) lock() {
	server.mtx.Lock()
}

func (server *dnsServer) unlock() {
	server.mtx.Unlock()
}

func NewDNSConnection(host string) (*dnsConnection, error) {
	dnsConn := &dnsConnection{
		isLocked: 0,
	}

	conn, err := dns.Dial("udp", host)
	if err != nil {
		return nil, err
	}

	dnsConn.conn = conn

	return dnsConn, nil
}

func (dnsConn *dnsConnection) Unwrap() interface{} {
	return dnsConn.conn
}

func (dnsConn *dnsConnection) IsLock() bool {
	d := atomic.LoadInt32(&dnsConn.isLocked)

	return d >= 1
}

func (dnsConn *dnsConnection) Close() error {
	dnsConn.isClosed = true
	return dnsConn.conn.Close()
}

func (dnsConn *dnsConnection) IsClosed() bool {
	return dnsConn.isClosed
}

func (dnsConn *dnsConnection) Lock() {
	atomic.StoreInt32(&dnsConn.isLocked, 1)
}

func (dnsConn *dnsConnection) Free() {
	atomic.StoreInt32(&dnsConn.isLocked, 0)
}

func NewDNSConnectionPool(size int, host string) (*dnsConnectionPool, error) {
	pool := &dnsConnectionPool{
		size: size,
		host: host,
		mtx:  &sync.Mutex{},
	}

	if size > 0 {
		for i := 0; i < size; i++ {
			conn, err := NewDNSConnection(host)
			if err != nil {
				return nil, err
			}

			pool.pool = append(pool.pool, conn)
		}

		go pool.reconnectChecker()
	}

	return pool, nil
}

func (pool *dnsConnectionPool) GetConnection() *dnsConnection {
	if pool.size == 0 {
		conn, err := NewDNSConnection(pool.host)
		if err != nil {
			fmt.Errorf("%v", err)
		}

		return conn
	}

	for {
		pool.mtx.Lock()

		for _, connection := range pool.pool {
			if connection.IsClosed() {
				continue
			}

			if !connection.IsLock() {
				conn := connection.Unwrap().(*dns.Conn)
				if addr := conn.LocalAddr(); addr == nil {
					connection.Close()
					continue
				}

				connection.Lock()

				pool.mtx.Unlock()

				return connection
			}
		}

		pool.mtx.Unlock()

		time.Sleep(time.Millisecond * 100)
	}
}

func (pool *dnsConnectionPool) FreeConnection(connection *dnsConnection) {
	if pool.size == 0 {
		connection.Close()
	} else {
		connection.Free()
	}
}

func (pool *dnsConnectionPool) GetHost() string {
	return pool.host
}

func (pool *dnsConnectionPool) reconnectChecker() {
	for {

		pool.mtx.Lock()

		newListPool := make([]*dnsConnection, 0)
		changePool := false

		for _, connection := range pool.pool {
			if connection.IsClosed() {
				changePool = true
			} else {
				newListPool = append(newListPool, connection)
			}
		}

		if changePool {
			for i := len(newListPool); i <= pool.size; i++ {
				conn, err := NewDNSConnection(pool.host)
				if err != nil {
					fmt.Errorf("%+v", err)
				}

				newListPool = append(newListPool, conn)
			}

			pool.pool = newListPool
		}

		pool.mtx.Unlock()

		time.Sleep(time.Second * 30)
	}
}

func collectStats(resolver *dnsResolver) {
	for {
		totalRequests := 0
		res := ""

		for _, inListServer := range resolver.servers {
			if !inListServer.IsSkipped() {
				totalRequests += inListServer.GetRequestCount()
			}
		}

		if totalRequests > 0 {

			res = "----Start stats----\n"
			for _, server := range resolver.servers {
				stats := fmt.Sprintf(`Server %s:
Total reqs: %d
To current Server req: %d
Ok: %d
NX: %d
Timeout: %d
Timeout quality (tc/rc): %f
NX quality (nx/rc): %f
Total quality (nx+tc/rc): %f
OkQuality: %f
avg time: %d
max time: %d
min time: %d
`,
					server.GetAddress(),
					totalRequests,
					server.GetRequestCount(),
					server.GetOkCount(),
					server.GetNXCount(),
					server.GetTimeoutCount(),
					float64(server.GetTimeoutCount())/float64(server.GetRequestCount()),
					float64(server.GetNXCount())/float64(server.GetRequestCount()),
					float64(server.GetTimeoutCount()+server.GetNXCount())/float64(server.GetRequestCount()),
					float64(server.GetOkCount())/float64(server.GetRequestCount()),
					server.GetAverageRequestTime().Milliseconds(),
					server.GetMaxRequestTime().Milliseconds(),
					server.GetMinRequestTime().Milliseconds())

				res += stats
				res += "--------------------\n"
			}
		}

		fmt.Println(res)
		time.Sleep(time.Second * 5)
	}
}
