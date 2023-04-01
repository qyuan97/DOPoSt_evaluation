#include <iostream>
#include <string>


#include "muhash.h"

using namespace std;

int main() {
    string s = "123456";
    auto mh = MuHash3072((unsigned char*)(s.data()), s.length());
    cout << "mh: " << mh.FinalizeBase64() << endl;
    string s2 = "78965464";
    mh.Insert((unsigned char*)(s2.data()), s2.length());

    cout << "H(a + b) = " << mh.FinalizeBase64() << endl;

    string s3 = "78965464";
    mh.Remove((unsigned char*)(s3.data()), s3.length());
    cout << "now: " << mh.FinalizeBase64() << endl;
//
//    //增量哈希计算
//    std::string s = "aaaaaa";
//    auto mh1 = MuHash3072((unsigned char*)(s.data()), s.length());
//    cout << "mh1: " << mh1.FinalizeBase64() << endl;
//    std::string s2 = "bbbbbb";
//    auto mh2 = MuHash3072((unsigned char*)(s2.data()), s2.length());
//    mh2 *= mh1; //哈希合并;
//    cout << "H(a) + H(b) = " << mh2.FinalizeBase64() << endl;

    return 0;
}
