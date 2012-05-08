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

    "code.google.com/p/x-go-binding/xgb"
)

// 
func try_shorten_host(host string) string {
    config_fd, err := os.Open("/etc/resolv.conf")
    if err != nil { return host }
    
    reader:= bufio.NewReaderSize(config_fd, 1024*1024)
    new_host := host
    
    for {
        bline, prefix, err := reader.ReadLine()
        line := string(bline)
        if err == io.EOF { break }
        if err != nil { log.Panic(err) }
        if prefix { log.Panic("Urgh, line >1mb in /etc/resolv.conf?!") }
        
        line = strings.TrimSpace(line)
        if len(line) == 0 { continue }
        
        fields := strings.Fields(line)
        if fields[0] == "host" || fields[0] == "search" {
            if len(fields) > 1 && strings.HasSuffix(host, fields[1]) {
                new_host = host[:len(host) - len(fields[1]) - 1]
            }
        }
    }
    return new_host
}

func parse_ssh_config() map[string] string {
    
    result := make(map[string] string)
    
    config_fd, err := os.Open(os.Getenv("HOME") + "/.ssh/config")
    if err != nil {
        log.Print(".. no ${HOME}/.ssh/config, won't map hostnames")
        return result
    }
    
    reader:= bufio.NewReaderSize(config_fd, 1024*1024)
    
    var currenthost string
    
    for {
        bline, prefix, err := reader.ReadLine()
        line := string(bline)
        if err == io.EOF { break }
        if err != nil { log.Panic(err) }
        if prefix { log.Panic("Urgh, line >1mb in ssh config?!") }
        
        line = strings.TrimSpace(line)
        if len(line) == 0 { continue }
        
        fields := strings.Fields(line)
        if fields[0] == "host" {
            currenthost = fields[1]
        } else if fields[0] == "hostname" {
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

func start_server(c *xgb.Conn, s *xgb.ScreenInfo, rl_execute_atom xgb.Id) {
    win := c.NewId()

    // Make a window which can be communicated with
    c.CreateWindow(0, win, s.Root, 0, 0, 1, 1, 0, 0, 0, 0, nil)
    
    c.ChangeProperty(xgb.PropModeReplace, win, rl_execute_atom, xgb.AtomString, 8, []byte("\x00"))
    c.ChangeWindowAttributes(win, xgb.CWEventMask, []uint32{xgb.EventMaskPropertyChange})
    
    get_execute_value := func() string {
        response, _ := c.GetProperty(false, win, rl_execute_atom,
                                     xgb.GetPropertyTypeAny, 0, 1024)
        result := string(response.Value)
        return result
    }
    
    log.Print("Ready and waiting..")
    // Event loop
    for {
        reply, err := c.WaitForEvent()
        if err != nil { log.Panic("Error in event loop:", err) }
        
        switch event := reply.(type) {
        case xgb.PropertyNotifyEvent:
            if event.Window == win && event.Atom == rl_execute_atom {
                values := strings.Split(get_execute_value(), "\x00")
                run(values)
            }
        }
    }
}

func connect(c *xgb.Conn, s *xgb.ScreenInfo, rl_execute_atom xgb.Id, args []string) {
    log.Println("Connecting with args:", args)
    
    tree, err := c.QueryTree(s.Root)
    if err != nil {
        log.Panic("QueryTree failed:", err)
    }
    
    // Broadcast a property request to every window
    results := make([]xgb.Cookie, len(tree.Children))
    for ch := range tree.Children {
        child := tree.Children[ch]
        results[ch] = c.GetPropertyRequest(false, child, rl_execute_atom, 
                                           xgb.GetPropertyTypeAny, 0, 1024)
    }
    
    success := false
    // Get the responses, look for windows that can recieve our command
    for i := range results {
        reply, err := c.GetPropertyReply(results[i])
        if err != nil {
            log.Panic("GetPropertyReply failed:", err)
        }
        if reply.ValueLen != 0 {
            c.ChangeProperty(xgb.PropModeReplace, tree.Children[i], rl_execute_atom, 
                             xgb.AtomString, 8, []byte(strings.Join(args, "\x00")))
            log.Println(" .. sent")
            success = true
        }
    }
    if success != true {
        log.Println(" .. server not running?")
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

    c, err := xgb.Dial(os.Getenv("DISPLAY"))
    if err != nil {
        log.Panic("cannot connect: %v\n", err)
    }
    defer c.Close()
    s := c.DefaultScreen()
    
    rl_execute_reply, _ := c.InternAtom(false, "RUNLOCAL_EXECUTE")
    rl_execute_atom := rl_execute_reply.Atom

    if *serve {
        start_server(c, s, rl_execute_atom)
    } else {
        if len(flag.Args()) == 0 { usage() }
        connect(c, s, rl_execute_atom, fixup_args(flag.Args()))
    }
}
