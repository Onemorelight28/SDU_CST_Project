from imwatermark import WatermarkEncoder
from PIL import Image


def embed_watermark(original_image_path, watermarked_image_path, watermark_text):
    # 初始化编码器
    encoder = WatermarkEncoder()
    encoder.set_watermark("bytes", watermark_text.encode("utf-8"))  # 文本转字节

    # 用OpenCV读取图片（invisible-watermark依赖OpenCV）
    import cv2

    img = cv2.imread(original_image_path)
    img_encoded = encoder.encode(img, "dwtDct")  # 嵌入水印
    cv2.imwrite(watermarked_image_path, img_encoded)  # 保存


# 测试
original_image = "original.png"
watermarked_image = "watermarked_image.png"
watermark_info = "Confidential: Project 2 - 2025"


embed_watermark(original_image, watermarked_image, watermark_info)
