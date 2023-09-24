# XLSX (Excel) 파일 파싱을 위한 라이브러리
import openpyxl

# XLSX 파일 파싱 함수
def parse_xlsx(file_path):
    workbook = openpyxl.load_workbook(file_path)
    for sheet in workbook.worksheets:
        for row in sheet.iter_rows():
            for cell in row:
                cell_value = cell.value
                # 셀 내용 출력
                print(f"XLSX Cell Value: {cell_value}")

# 파일 경로 지정
file_path = "example.xlsx"  # 예제 XLSX 파일의 경로로 수정

if file_path.endswith(".xlsx"):
    parse_xlsx(file_path)
