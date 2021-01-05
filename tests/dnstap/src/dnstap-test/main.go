package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/cloudflare/dns"
	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/golang/protobuf/proto"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

var (
	kresdArgs = []string{
		"-n",
		"-q",
	}
)

func qnameFromFrame(b []byte) (string, error) {
	dt := &dnstap.Dnstap{}
	var name string
	if err := proto.Unmarshal(b, dt); err != nil {
		return name, err
	}

	var msg_raw []byte
	m := dt.Message
	if *m.Type == dnstap.Message_CLIENT_QUERY {
		msg_raw = m.QueryMessage
	} else if *m.Type == dnstap.Message_CLIENT_RESPONSE {
		msg_raw = m.ResponseMessage
	} else {
		return name, fmt.Errorf("incorrect message type: %v", *m.Type)
	}

	if msg_raw == nil {
		return name, fmt.Errorf("no message payload")
	}
	if err := dns.IsMsg(msg_raw); err != nil {
		return name, err
	}
	var msg dns.Msg
	if err := msg.Unpack(msg_raw); err != nil {
		return name, err
	}
	if len(msg.Question) < 1 {
		return name, fmt.Errorf("question empty")
	}
	return msg.Question[0].Name, nil
}

func listenOn() (net.Addr, *os.File, error) {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 0,
	})
	if err != nil {
		return nil, nil, err
	}

	file, err := udpConn.File()
	if err != nil {
		return nil, nil, err
	}
	return udpConn.LocalAddr(), file, nil
}

func runKresd(ctx context.Context, path, configFile string, grace time.Duration) (chan bool, error) {
	ch := make(chan bool)
	kresdArgs = append(kresdArgs, "-c"+configFile)
	// we have 1 object in ExtraFiles with index 0
	// child fd will be 3 + i = 3
	kresdArgs = append(kresdArgs, "-S3")

	file := ctx.Value("file").(*os.File)
	debug := ctx.Value("debug").(bool)

	cmd := exec.CommandContext(ctx, path, kresdArgs...)
	cmd.ExtraFiles = []*os.File{file}

	var stdout, stderr io.ReadCloser
	var err error
	if debug {
		stdout, err = cmd.StdoutPipe()
		if err != nil {
			log.Printf("stdoutpipe: %v\n", err)
			return ch, err
		}

		stderr, err = cmd.StderrPipe()
		if err != nil {
			log.Printf("stderrpipe: %v\n", err)
			return ch, err
		}
	}

	go func() {
		status := false
		defer func() {
			ch <- status // kresd done
		}()
		if err := cmd.Start(); err != nil {
			log.Printf("start: %v\n", err)
			return
		}
		time.Sleep(grace)
		ch <- true // Started kresd

		if debug {
			s, err := ioutil.ReadAll(stdout)
			if err != nil {
				log.Printf("readall: %v\n", err)
				return
			}
			if len(s) > 0 {
				fmt.Printf("stdout:\n%s\n", s)
			}

			s, err = ioutil.ReadAll(stderr)
			if err != nil {
				log.Printf("readall: %v\n", err)
				return
			}
			if len(s) > 0 {
				fmt.Printf("stderr:\n%s\n", s)
			}
		}

		if err := cmd.Wait(); err != nil && err.Error() != "signal: killed" {
			log.Printf("wait: %v\n", err)
			return
		}
		status = true
	}()
	return ch, nil
}

func main() {
	var (
		unixSocket = flag.String("u", "dnstap.sock", "dnstap socket")
		kresdPath  = flag.String("cmd", "kresd", "kresd path")
		configFile = flag.String("c", "config", "config file")
		qnames     = flag.String("q", ".", "list of comma separated zones")
		grace      = flag.String("g", "1s", "Time to wait for daemon start")
		timeout    = flag.String("t", "60s", "Test Timeout")
		debug      = flag.Bool("d", false, "Debug")
	)

	flag.Parse()

	kresdStartGracePeriod, err := time.ParseDuration(*grace)
	if err != nil {
		panic(err)
	}

	testTimeout, err := time.ParseDuration(*timeout)
	if err != nil {
		panic(err)
	}

	input, err := dnstap.NewFrameStreamSockInputFromPath(*unixSocket)
	if err != nil {
		panic(err)
	}

	output := make(chan []byte)
	go input.ReadInto(output)

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)

	// Create a UDP listening socket on random port
	// FD will be passed on to kresd
	addr, file, err := listenOn()
	if err != nil {
		panic(err)
	}
	if *debug {
		log.Printf("listen addr:%v", addr)
	}
	ctx = context.WithValue(ctx, "file", file)
	ctx = context.WithValue(ctx, "debug", *debug)

	ch, err := runKresd(ctx, *kresdPath, *configFile, kresdStartGracePeriod)
	if err != nil {
		panic(err)
	}

	log.Printf("Waiting for kresd to start\n")
	status := <-ch
	if !status {
		os.Exit(1) // error starting
	}

	go func() {
		parts := strings.Split(*qnames, ",")

		if len(parts) == 0 {
			log.Printf("qname count is 0")
		}
		for _, name := range parts {
			m := new(dns.Msg)
			fqdn := dns.Fqdn(name)
			m.SetQuestion(fqdn, dns.TypeA)
			c := new(dns.Client)
			resp, _, err := c.Exchange(m, fmt.Sprintf("%v", addr))
			if err != nil {
				log.Printf("%v\n", err)
				os.Exit(1) // Test Failed
			}
			if *debug {
				log.Printf("Response: %v", resp)
			}

			for range "QR" { // Checking Query and Response is the same ATM
				o := <-output
				if *debug {
					log.Printf("raw dnstap:%v", o)
				}
				dtName, err := qnameFromFrame(o)
				if err != nil {
					log.Printf("%v\n", err)
					os.Exit(1)
				}
				if fqdn != dtName {
					log.Printf("expected %v got %v", fqdn, dtName)
					os.Exit(1) // Test failed
				}
				log.Printf("matched qname: %v", dtName)
			}
		}
		cancel() // Send signal to close daemon
	}()

	status = <-ch
	if !status {
		os.Exit(1) // error in wait
	}
	log.Printf("Tested OK\n")
}
