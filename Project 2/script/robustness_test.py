from PIL import Image, ImageEnhance
from imwatermark import WatermarkDecoder
import cv2
import numpy as np


def decode_watermark(image_path, wm_length_bits=32):
    """尝试从图片中解码水印"""
    decoder = WatermarkDecoder("bytes", wm_length_bits)
    img = cv2.imread(image_path)
    try:
        watermark = decoder.decode(img, "dwtDct")
        return watermark.decode("utf-8", errors="ignore")
    except Exception as e:
        return f"解码失败: {str(e)}"


def test_robustness(watermarked_image_path, original_watermark):
    """
    对带水印的图片进行鲁棒性测试并验证水印可读性

    参数:
    watermarked_image_path (str): 带水印的图片路径
    original_watermark (str): 原始水印文本（用于验证）
    """
    try:
        img = Image.open(watermarked_image_path)
        print(f"\n原始水印内容: '{original_watermark}'")
        print(f"原始图片解码结果: {decode_watermark(watermarked_image_path, len(original_watermark)*8)}")

        # 1. 翻转测试
        img_flipped = img.transpose(Image.FLIP_LEFT_RIGHT)
        img_flipped.save("attacked_flipped.png")
        print("\n[翻转测试] 解码结果:", decode_watermark("attacked_flipped.png", len(original_watermark) * 8))

        # 2. 平移测试
        width, height = img.size
        translated_img = Image.new(img.mode, img.size, color="black")
        region = img.crop((0, 0, width - 50, height))
        translated_img.paste(region, (50, 0))
        translated_img.save("attacked_translated.png")
        print("[平移测试] 解码结果:", decode_watermark("attacked_translated.png", len(original_watermark) * 8))

        # 3. 截取测试
        left, top = width * 0.25, height * 0.25
        right, bottom = width * 0.75, height * 0.75
        img_cropped = img.crop((left, top, right, bottom))
        img_cropped.save("attacked_cropped.png")
        print("[截取测试] 解码结果:", decode_watermark("attacked_cropped.png", len(original_watermark) * 8))

        # 4. 对比度测试
        enhancer = ImageEnhance.Contrast(img)
        img_contrasted = enhancer.enhance(1.8)
        img_contrasted.save("attacked_contrasted.png")
        print("[对比度测试] 解码结果:", decode_watermark("attacked_contrasted.png", len(original_watermark) * 8))

    except Exception as e:
        print(f"鲁棒性测试出错: {e}")


if __name__ == "__main__":
    # 注意：这里的水印需要与嵌入时一致
    watermarked_image = "watermarked_image.png"
    original_wm = "Confidential: Project 2 - 2025"  # 必须与嵌入的水印相同
    test_robustness(watermarked_image, original_wm)
