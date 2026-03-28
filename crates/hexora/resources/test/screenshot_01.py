import PIL
import d3dshot
import mss
import pyautogui
import pyscreenshot
from PIL import ImageGrab


ImageGrab.grab()
PIL.ImageGrab.grab()
pyscreenshot.grab()
pyautogui.screenshot()
mss.mss().grab({"left": 0, "top": 0, "width": 200, "height": 100})
d3dshot.create().screenshot()
