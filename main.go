// TODO: Detection of multiple servers running
// TODO: Detect local vs remote running (so that gedit could be a permanent 
//                                          alias to "rl gedit", for example)

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	//"code.google.com/p/x-go-binding/xgb"
	"github.com/BurntSushi/xgb"
	"github.com/BurntSushi/xgb/xproto"
)

const atomname = "RUNLOCAL_EXECUTE"

// 
func try_shorten_host(host string) string {
	config_fd, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return host
	}

	reader := bufio.NewReaderSize(config_fd, 1024*1024)
	new_host := host

	for {
		bline, prefix, err := reader.ReadLine()
		line := string(bline)
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Panic(err)
		}
		if prefix {
			log.Panic("Urgh, line >1mb in /etc/resolv.conf?!")
		}

		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		fields := strings.Fields(line)
		if fields[0] == "host" || fields[0] == "search" {
			if len(fields) > 1 && strings.HasSuffix(host, fields[1]) {
				new_host = host[:len(host)-len(fields[1])-1]
			}
		}
	}
	return new_host
}

func parse_ssh_config() map[string]string {

	result := make(map[string]string)

	config_fd, err := os.Open(os.Getenv("HOME") + "/.ssh/config")
	if err != nil {
		log.Print(".. no ${HOME}/.ssh/config, won't map hostnames")
		return result
	}

	reader := bufio.NewReaderSize(config_fd, 1024*1024)

	var currenthost string

	for {
		bline, prefix, err := reader.ReadLine()
		line := string(bline)
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Panic(err)
		}
		if prefix {
			log.Panic("Urgh, line >1mb in ssh config?!")
		}

		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		fields := strings.Fields(line)
		if strings.ToLower(fields[0]) == "host" {
			currenthost = fields[1]
		} else if strings.ToLower(fields[0]) == "hostname" {
			result[fields[1]] = currenthost
		}
	}

	return result
}

func map_file_args(host, cmd string, args []string) []string {
	host = try_shorten_host(host)
	mapping := parse_ssh_config()
	replacement, ok := mapping[host]
	if !ok {
		log.Print("Host not in mapping: ", host, " ", replacement)
		replacement = host
	}
	replacement = "sftp://" + replacement
	for i := range args {
		if strings.HasPrefix(args[i], "file:") {
			args[i] = strings.Replace(args[i], "file:", replacement, 1)
		}
	}
	return args
}

func run(args []string) {
	host, cmd := args[0], args[1]
	args = args[2:]

	args = map_file_args(host, cmd, args)

	log.Print("Executing: ", cmd, args)
	p := exec.Command(cmd, args...)
	stdout, _ := p.StdoutPipe()
	err := p.Start()
	if err != nil {
		log.Print("Unable to run", cmd, ":", err)
	}
	go func() {
		bytes := make([]byte, 1024)
		for {
			n, err := stdout.Read(bytes)
			if err != nil {
				break
			}
			log.Print("output: ", n, string(bytes))
		}
		p.Wait()
		log.Print("Program exited")
	}()
}

func start_server(c *xgb.Conn, s *xproto.ScreenInfo, rl_execute_atom xproto.Atom) {
	win, err := xproto.NewWindowId(c)
	if err != nil {
		panic(err)
	}

	// Make a window which can be communicated with
	err = xproto.CreateWindowChecked(c, s.RootDepth, win, s.Root, 0, 0, 1, 1, 0, 0, 0, 0, nil).Check()
	if err != nil {
		panic(err)
	}

	err = xproto.ChangePropertyChecked(c, xproto.PropModeReplace, win,
		rl_execute_atom, xproto.AtomString, 8, xproto.PropModeReplace,
		[]byte("\x00")).Check()
	if err != nil {
		panic(err)
	}
	err = xproto.ChangeWindowAttributesChecked(c, win, xproto.CwEventMask, []uint32{xproto.EventMaskPropertyChange}).Check()
	if err != nil {
		panic(err)
	}

	get_execute_value := func() string {
		response, err := xproto.GetProperty(c, false, win, rl_execute_atom,
			xproto.GetPropertyTypeAny, 0, 1024).Reply()
		if err != nil {
			panic(err)
		}
		result := string(response.Value)
		return result
	}

	log.Print("Ready and waiting..")
	// Event loop
	for {
		reply, err := c.WaitForEvent()
		if err != nil {
			log.Panic("Error in event loop:", err)
		}

		switch event := reply.(type) {
		case xproto.PropertyNotifyEvent:
			if event.Window == win && event.Atom == rl_execute_atom {
				values := strings.Split(get_execute_value(), "\x00")
				run(values)
			}
		}
	}
}

func connect(c *xgb.Conn, s *xproto.ScreenInfo, rl_execute_atom xproto.Atom, args []string) {
	log.Println("Connecting with args:", args)

	tree, err := xproto.QueryTree(c, s.Root).Reply()
	if err != nil {
		log.Panic("QueryTree failed:", err)
	}

	// Broadcast a property request to every window
	results := make([]xproto.GetPropertyCookie, len(tree.Children))
	for ch, child := range tree.Children {
		results[ch] = xproto.GetProperty(c, false, child,
			rl_execute_atom, xproto.GetPropertyTypeAny, 0, 1024)
	}

	success := false
	// Get the responses, look for windows that can recieve our command
	for i, r := range results {
		reply, err := r.Reply()
		if err != nil {
			log.Panic("GetPropertyRequest failed:", err)
		}
		if reply.Format != 0 {
			data := []byte(strings.Join(args, "\x00"))
			err = xproto.ChangePropertyChecked(c, xproto.PropModeReplace, tree.Children[i],
				rl_execute_atom, xproto.AtomString, 8, uint32(len(data)), data).Check()
			log.Println(" .. sent")
			success = true
		}
	}
	if success != true {
		log.Println(" .. server not running? atom = ", rl_execute_atom)
	}
}

// Prepend the hostname to args and insert file: at the beginning of files
func fixup_args(args []string) []string {
	fixed_args := make([]string, len(args))
	copy(fixed_args, args)
	for i := range fixed_args {
		if strings.HasPrefix(fixed_args[i], "file:") {
			path, _ := filepath.Abs(fixed_args[i][len("file:"):])
			fixed_args[i] = "file:" + path
		} else if _, notexists := os.Stat(fixed_args[i]); notexists == nil {
			path, _ := filepath.Abs(fixed_args[i])
			fixed_args[i] = "file:" + path
		}
	}

	// result = [host] [args...]
	result := make([]string, 0, len(args)+1)
	host, _ := os.Hostname()
	result = append(result, host)
	result = append(result, fixed_args...)
	return result
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: runlocal [-serve]\n       runlocal program [args...]\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {

	var serve *bool = flag.Bool("serve", false, "Listen for connections")

	flag.Usage = usage
	flag.Parse()

	if remote := os.Getenv("SSH_CONNECTION"); remote == "" && len(flag.Args()) != 0 {
		invoked_as := os.Args[0]
		actual_binary, err := os.Readlink("/proc/self/exe")
		if err != nil {
			log.Panic("/proc/self/exe doesn't exist!")
		}
		log.Print("Invoked as: '", invoked_as, "' (actual=", actual_binary, ")")
		log.Panic("Not yet implemented: Would have run locally")
		return
	}

	c, err := xgb.NewConn()
	if err != nil {
		log.Panic("cannot connect: %v\n", err)
	}
	s := xproto.Setup(c).DefaultScreen(c)

	rl_execute_reply, err := xproto.InternAtom(c, false, uint16(len(atomname)), atomname).Reply()
	if err != nil {
		panic(err)
	}
	rl_execute_atom := rl_execute_reply.Atom

	if *serve {
		//log.Printf("c = %v, s = %v, a = %v", c, s, rl_execute_atom)
		start_server(c, s, rl_execute_atom)
	} else {
		if len(flag.Args()) == 0 {
			usage()
		}
		connect(c, s, rl_execute_atom, fixup_args(flag.Args()))
	}
}
