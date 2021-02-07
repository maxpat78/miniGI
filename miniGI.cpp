/*
    miniGI.CPP - A minimalist proxy Gateway Interface for NGINX

    Start a server on given localhost's port and process incoming HTTP requests
    to execute script/apps and respond with their output. MS WINDOWS ONLY!
*/
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include <regex>

#include <winsock2.h>
#include <direct.h>
#include <windows.h>

// MSVC #pragma
#pragma comment(lib,"ws2_32.lib") // Winsock Library
#pragma comment(lib,"shell32.lib") // SHELL32 Library

using namespace std;


inline bool iends_with(string & value, string&& ending) {
    if (ending.size() > value.size()) return false;
    transform(value.begin(), value.end(), value.begin(), ::toupper);
    return equal(ending.rbegin(), ending.rend(), value.rbegin());
}


class myPopen {
public:
    myPopen(string&& q) {
        query = q;
        ParseQuery();
    
        char result[MAX_PATH];
    
        if (iends_with(app, string("BAT")) || iends_with(app, string("CMD"))) {
            lstrcpy(result, getenv("COMSPEC"));
            lstrcat(result, " /C");
        }
        else {
            // Find the app associated with the script 
            if ((DWORD)FindExecutable(app.c_str(), 0, (LPSTR)&result) < 33) {
                cerr << "FindExecutable failed!" << endl;
                return;
            }
            else
                cerr << "FindExecutable found " << result << endl;
        }

        cmdline = string(result) + " " + app.substr(cwd.length()+1) + " " + cmdline;

        cerr << "cmdline set to " << cmdline << endl;

        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);

        ZeroMemory(&pi, sizeof(pi));
    
        SECURITY_ATTRIBUTES saAttr;
        saAttr.nLength = sizeof(SECURITY_ATTRIBUTES); 
        saAttr.bInheritHandle = TRUE; 
        saAttr.lpSecurityDescriptor = NULL; 

        // Create 2 pipes and associate them to process STDIN & STDOUT
        if (!CreatePipe(&hRdIn, &hWrIn, &saAttr, 0) || !CreatePipe(&hRdOut, &hWrOut, &saAttr, 0) ) {
            cerr << "Couldn't create a PIPE!" << endl;
            return;
        }
    
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.hStdInput = hRdIn;
        si.hStdOutput = hWrOut;
        si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
        si.wShowWindow = SW_HIDE;

        //~ BOOL WINAPI CreateProcess(
          //~ _In_opt_    LPCTSTR               lpApplicationName,
          //~ _Inout_opt_ LPTSTR                lpCommandLine,
          //~ _In_opt_    LPSECURITY_ATTRIBUTES lpProcessAttributes,
          //~ _In_opt_    LPSECURITY_ATTRIBUTES lpThreadAttributes,
          //~ _In_        BOOL                  bInheritHandles,
          //~ _In_        DWORD                 dwCreationFlags,
          //~ _In_opt_    LPVOID                lpEnvironment,
          //~ _In_opt_    LPCTSTR               lpCurrentDirectory,
          //~ _In_        LPSTARTUPINFO         lpStartupInfo,
          //~ _Out_       LPPROCESS_INFORMATION lpProcessInformation
        //~ );
        if (! CreateProcess(0, (LPSTR) cmdline.c_str(), 0, 0, 1, CREATE_NEW_CONSOLE, 0, cwd.c_str(), &si, &pi))
            cerr << "CreateProcess failed!" << endl;
        else
        {
            isProcStarted = true;
            cerr << "isProcStarted set to true: " << isProcStarted << endl;
        }
        // Since the handles were inherited, close their local copy
        // (or I/O will get blocked on child's exit)
        CloseHandle(hRdIn);
        CloseHandle(hWrOut);
        CloseHandle(hWrIn); // Actually we don't handle piping to STDIN
    }

    ~myPopen() {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    size_t Read(char* buffer, size_t length) {
        // Called app/script MUST terminate the header with a Content-Type
        // or the browser could try to download something
        size_t n;
        //~ cerr << "myPopen::Read calling ReadFile..." << endl;
        if (! ReadFile(hRdOut, buffer, length, (LPDWORD) &n, 0) || !n) {
            //~ cerr << "ReadFile failed/Stream end!" << endl;
            return 0;
        }
        //~ cerr << "myPopen::Read " << n << " bytes from pipe" << endl;
        //~ buffer[n] = '\0';
        //~ cerr << buffer << endl;
        return n;
    }

    void ParseQuery() {
        // i.e. cgi-bin/a.bat?hello+you&a=1 or cgi-bin/a.bat?hello%20you
        size_t pos = query.find('?');
        if (pos != string::npos) {
            app = query.substr(0, pos);
            cmdline = query.substr(pos+1);
        }
        else {
            app = query;
            cmdline = "";
        }
        replace(app.begin(), app.end(), '/', '\\');

        if (! cmdline.empty()) {
            // Replace any %20 with space
            for (size_t p=0; (p = cmdline.find("%20", p)) != string::npos; )
                cmdline.replace(p, 3, " ");
            // Split string at +
            regex re("\\+");
            sregex_token_iterator first{cmdline.begin(), cmdline.end(), re, -1}, last;
            vector<string> v = {first, last};
            ostringstream oss;
            copy(v.begin(), v.end(), ostream_iterator<string>(oss, " "));
            cmdline = oss.str();
        }
    
        pos = app.rfind('\\');
        if (pos != string::npos) {
            cwd = app.substr(0, pos).c_str();
        }
        else
            cwd = "";
        cerr << "ParseQuery: app=" << app << " cmdline=" << cmdline << " CWD=" << cwd << endl;
    }

    bool isOpen() {
        return isProcStarted;
    }

private:
    bool isProcStarted = false;
    string query;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    HANDLE hRdIn, hWrIn, hRdOut, hWrOut;
public:
    string app;
    string cmdline;
    string cwd;
};


void event_handler(HANDLE h) {
    WaitForSingleObject(h, INFINITE);
    ExitProcess(0);
}



void connection_handler(SOCKET s) {
    char request[4096];
    int req_size;

    if((req_size = recv(s, request, sizeof(request), 0)) == SOCKET_ERROR) {
        cerr << "Can't receive the request, error #" << WSAGetLastError() << endl;
        return;
    }
    request[req_size] = '\0';

    string req(request);
    // i.e. GET /cgi-bin/a.bat?hello HTTP/1.0
    regex rx("GET /(.+) HTTP/1.[01]");
    smatch m;

    cerr << req << endl;

    if (! regex_search(req, m, rx)) {
        cerr << "Unknown HTTP request" << endl;
        return;
    }

    myPopen p = myPopen(m[1].str());

    if (p.isOpen()) {
        size_t n;
        char buf[4096];
        static char resp[] = "HTTP/1.0 200 OK\n";
        // Mandatory before any output
        send(s, resp, sizeof(resp)-1, 0);
        while ((n=p.Read(buf, sizeof(buf)))) {
            //~ cerr << "Read " << n << " bytes from pipe" << endl;
            send(s, buf, n, 0);
        }
    }
    else {
        static char resp[] = "HTTP/1.0 400 BAD REQUEST\n\n";
        send(s, resp, sizeof(resp)-1, 0);
        cerr << "myPopen failed!" << endl;
    }
    cerr << endl;

    shutdown(s, SD_SEND);
    closesocket(s);
}





int main(int argc , char *argv[])
{
    // Redirect CERR (STDERR) to log file
    ofstream out("minigi.log", ios::app);
    cerr.rdbuf(out.rdbuf());

    if (argc < 2) {
        cerr << "Bad syntax. Use minicgi <port> (on localhost)" << endl;
        return 1;
    }

    int port_number = atoi(argv[1]);
    if (port_number==0 || port_number > 65535) {
        cerr << "Wrong port number!" << endl;
        return 1;
    }

    string event_str = "MINIGI_EVENT_PORT_";
    event_str += argv[1];

    // mingw shell silently converts /Q in Q:/ (assumes a root path)
    if (argc>2 && (!_stricmp(argv[2], "-Q") || !_stricmp(argv[2], "/Q"))) {
        // STOP mini server
        HANDLE hEvent = OpenEvent(EVENT_MODIFY_STATE, 0, event_str.c_str());
        if (hEvent) {
            if (! SetEvent(hEvent))
                cerr << "SetEvent failed with code " << hex << GetLastError() << endl;
            else
                cerr << "STOP signal sent!" << endl;
        }
        else
            cerr << "Could not open handle to Event " << event_str.c_str() << endl;
        ExitProcess(1);
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        cerr << "Can't initialize Windows Socket: error #" << WSAGetLastError() << endl;
        return 1;
    }

    SOCKET s;
    if((s = socket(AF_INET , SOCK_STREAM , 0 )) == INVALID_SOCKET) {
        cerr << "Can't make a socket: error #" << WSAGetLastError() << endl;
        WSACleanup();
        return 1;
    }

    struct sockaddr_in server;

    server.sin_family = AF_INET;
    server.sin_addr.s_addr =  inet_addr("127.0.0.1");
    server.sin_port = htons(port_number);
    
    if (::bind(s, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR) {
        cerr << "Can't bind socket, error #" << WSAGetLastError() << endl;
        return 1;
    }

    HANDLE hEvent = CreateEvent(0, true, false, event_str.c_str());
    cerr << "CreateEvent succeeded" << endl;
    if (hEvent && (GetLastError() != ERROR_ALREADY_EXISTS))
        thread(event_handler, hEvent).detach();
    else {
        cerr << "Attempt to start a new listener on port " << port_number << " failed, already exists!" << endl;
        return 1;
    }

    listen(s , 3);
    cerr << "Listening..." << endl;
    
    int c = sizeof(struct sockaddr_in);
    struct sockaddr_in client;
    SOCKET connection;

    while((connection = accept(s, (struct sockaddr *)&client, &c)) != INVALID_SOCKET)
        thread(connection_handler, connection).detach();

    if (connection == INVALID_SOCKET)
        cerr << "Can't accept the connection, error #" << WSAGetLastError() << endl;

    closesocket(s);
    WSACleanup();
    
    cerr << "Exiting..." << endl << endl;
    
    return 0;
}
