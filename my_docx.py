# DOCX (Word) 파일 파싱을 위한 라이브러리
from docx import Document

# DOCX 파일 파싱 함수
def parse_docx(file_path):
    doc = Document(file_path)
    for paragraph in doc.paragraphs:
        text = paragraph.text
        # 문단 내용 출력
        print(f"DOCX Paragraph: {text}")

# 파일 경로 지정
file_path = "example.docx"  # 예제 DOCX 파일의 경로로 수정

if file_path.endswith(".docx"):
    parse_docx(file_path)
