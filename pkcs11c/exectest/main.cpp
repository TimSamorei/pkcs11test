
// A C++ program that compiles and runs another C++
// program
#include <bits/stdc++.h>
using namespace std;
int main ()
{

    string mystring;
    // Build command to execute.  For example if the input
    // file name is a.cpp, then str holds "gcc -o a.out a.cpp"
    // Here -o is used to specify executable file name
    string str = "";
    str = str + "java -jar exetest.jar Tim";
    string second = "\n";

    // Convert string to const char * as system requires
    // parameter of type const char *
    const char *command = str.c_str();
    const char *command2 = second.c_str();

    cout << "Execing command: " << command << endl;
    system(command) >> mystring;
    system(command);
    system(command2);
    cout << "Input was: " << mystring << endl;

    return 0;
}

