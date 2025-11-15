#include <iostream>
void test(int* num) {
    std::cout << num << std::endl;
    return;
}
int y = 1;
int* x = &y;
int main() {
    test(x);
}