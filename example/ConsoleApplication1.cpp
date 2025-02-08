#include <stdio.h>
#include <string.h>

void vulnerable_function(char* input) {
    char buffer[3];
    // 不安全的 strcpy 函数，导致缓冲区溢出
    strcpy(buffer, input);
    printf("Buffer content: %s\n", buffer);
}

int main() {
    char input[256];
    printf("Enter input: ");
    // 获取输入，用户可以输入超过 buffer 大小的数据
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = '\0'; // 去除换行符
    vulnerable_function(input);  // 调用存在漏洞的函数
    return 0;
}
