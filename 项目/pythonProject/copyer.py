import pyperclip as clip
import pyautogui as gui
import time
file_path = 'C:/Users/MX69/Desktop/cn.txt'
before_start = 5
between_lines = 0.2

paste_keys = ['ctrl', 'v']

def read_file(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip()]
        return lines
    except FileNotFoundError:
        print("未找到文件，请检查路径")
        return []
def auto_paste():
    sentences = read_file(file_path)
    if not sentences:
        print("无内容可复制，脚本退出")
        return
    print(f"找到{len(sentences)}句话准备处理")
    print(f"请在 {before_start} 秒内将鼠标焦点切换到目标输入框...")
    time.sleep(before_start)
    print("开始执行")
    for i, sentence in enumerate(sentences):
        clip.copy(sentence)
        gui.hotkey(*paste_keys)
        gui.press('enter')
        time.sleep(between_lines)
    print("执行完毕")
if __name__ == '__main__':
    auto_paste()