#include "stdafx.h"
#include "PEHelper.h"

CPEHelper::CPEHelper(void)
{
	m_hFile = INVALID_HANDLE_VALUE;
	m_hFileMapping = NULL;
	m_pBuffer = NULL;
	m_pImageDosHeader = NULL;
	m_pImageFileHeader = NULL;
	m_pNtHeader = NULL;
	m_dwMchine = 0;
}


CPEHelper::~CPEHelper(void)
{
	InternalClean();
}

VOID CPEHelper::InternalClean()
{
	if (m_pBuffer)
	{
		::UnmapViewOfFile(m_pBuffer);
		m_pBuffer = NULL;
	}

	if (m_hFileMapping)
	{
		::CloseHandle(m_hFileMapping);
		m_hFileMapping = NULL;
	}

	if (INVALID_HANDLE_VALUE != m_hFile)
	{
		::CloseHandle(m_hFile);
		m_hFile = INVALID_HANDLE_VALUE;
	}

	m_pImageDosHeader = NULL;
	m_pImageFileHeader = NULL;
	m_pNtHeader = NULL;
	m_dwMchine = 0;
}

ULONG CPEHelper::RVAToFOA(DWORD ulRva)
{
	if (m_pNtHeader && m_pImageFileHeader)
	{
		PIMAGE_SECTION_HEADER pImageSectionHeader =
			((PIMAGE_SECTION_HEADER) ((ULONG_PTR)(m_pImageFileHeader) + sizeof(IMAGE_FILE_HEADER) + m_pImageFileHeader->SizeOfOptionalHeader));

		// 遍历节表，查找目标RVA所属的节表，并且算出FOA
		for(int i=0; i < m_pImageFileHeader->NumberOfSections; i++)
		{
			if ((ulRva >= pImageSectionHeader[i].VirtualAddress) && 
				(ulRva <= pImageSectionHeader[i].VirtualAddress + pImageSectionHeader[i].SizeOfRawData))
			{
				return pImageSectionHeader[i].PointerToRawData + (ulRva - pImageSectionHeader[i].VirtualAddress);
			} 
		}
	}

	return 0;
}

#define IfFalseGoExit(x) { br=(x); if (!br) goto _Error; }
BOOL CPEHelper::OpenAndVerify(LPCTSTR pFilePathName)
{
	BOOL br = FALSE;

	LPVOID pNtHeaders = NULL;
	DWORD dwE_lfanew = 0;
	DWORD dwPESignature = 0;
	ULONG ulAddressTemp = 0;

	m_hFile = ::CreateFile(
		pFilePathName, GENERIC_READ, FILE_SHARE_READ, 
		NULL, OPEN_EXISTING, NULL, NULL);
	IfFalseGoExit(INVALID_HANDLE_VALUE != m_hFile);
	IfFalseGoExit(NULL != m_hFile);

	m_hFileMapping = ::CreateFileMapping(
		m_hFile, 0, PAGE_READONLY, 0, 0, NULL);
	IfFalseGoExit(NULL != m_hFileMapping);

	m_pBuffer = ::MapViewOfFile(
		m_hFileMapping, FILE_MAP_READ, 0, 0, 0);
	IfFalseGoExit(NULL != m_pBuffer);

	//　检查文件大小
	DWORD dwFileSize = GetFileSize(m_hFile, NULL);
	IfFalseGoExit(INVALID_FILE_SIZE != dwFileSize);
	IfFalseGoExit(dwFileSize > (sizeof(IMAGE_DOS_HEADER)));

	// 对比MZ签名
	m_pImageDosHeader = (PIMAGE_DOS_HEADER)(m_pBuffer);
	IfFalseGoExit(IMAGE_DOS_SIGNATURE == m_pImageDosHeader->e_magic);

	// 对比PE签名
	dwE_lfanew = m_pImageDosHeader->e_lfanew;
	ulAddressTemp = PtrToUlong(m_pBuffer) + dwE_lfanew;

	dwPESignature  = *((PDWORD)ULongToPtr(ulAddressTemp));
	IfFalseGoExit(IMAGE_NT_SIGNATURE == dwPESignature);

	// 因为还不确定是PE32或PE64，所以先保存IMAGE_NT_HEADER的地址
	m_pNtHeader = ULongToPtr(ulAddressTemp);

	// 获取IMAGE_FILE_HEADER，然后判断目标平台CPU类型
	ulAddressTemp = ulAddressTemp + sizeof(IMAGE_NT_SIGNATURE);
	m_pImageFileHeader = (PIMAGE_FILE_HEADER)ULongToPtr(ulAddressTemp);

	if (IMAGE_FILE_MACHINE_I386 == m_pImageFileHeader->Machine)
	{
		// 初步判断为PE32，继续检测OptionalHeader中的Magic
		PIMAGE_NT_HEADERS32 pImageNtHeader32 = 
			(PIMAGE_NT_HEADERS32)m_pNtHeader;

		IfFalseGoExit(
			IMAGE_NT_OPTIONAL_HDR32_MAGIC == pImageNtHeader32->OptionalHeader.Magic);
		// 确定为PE32
		m_dwMchine = IMAGE_FILE_MACHINE_I386;
	}
	else if(IMAGE_FILE_MACHINE_AMD64 == m_pImageFileHeader->Machine)
	{
		// 初步判断为PE64，继续检测OptionalHeader中的Magic
		PIMAGE_NT_HEADERS64 pImageNtHeader64 = 
			(PIMAGE_NT_HEADERS64)m_pNtHeader;

		IfFalseGoExit(
			IMAGE_NT_OPTIONAL_HDR64_MAGIC == pImageNtHeader64->OptionalHeader.Magic);
		// 确定为PE64
		m_dwMchine = IMAGE_FILE_MACHINE_AMD64;
	}
	else
	{
		// 不支持的类型
		IfFalseGoExit(FALSE);
	}

	return TRUE;

_Error:
	InternalClean();

	return br;
}


//************************************
// Method:    GetPDBFilePath
// FullName:  CPEHelper::GetPDBFilePath
// Access:    public 
// Returns:   VOID
// Qualifier:
// Parameter: CString & strPdbPath
//			 从PE文件中读取调试信息中的PDB信息(如果存在)
//************************************
VOID CPEHelper::GetPDBInfo(CString& strPDBFileName, CString& strPDBSignature, DWORD& dwPDBAge)
{
	strPDBFileName.Empty();
	strPDBSignature.Empty();
	dwPDBAge = 0;

	if (NULL == m_pNtHeader)
	{
		return ;
	}

	ULONG ulDebugDirectoryRVA = 0;
	int nDirectoryItemCount = 0;

	if (IMAGE_FILE_MACHINE_I386 == m_dwMchine)
	{
		PIMAGE_NT_HEADERS32 pImageNtHeader32 = 
			(PIMAGE_NT_HEADERS32)m_pNtHeader;

		ulDebugDirectoryRVA = 
			pImageNtHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
		DWORD dwSize = 
			pImageNtHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;

		nDirectoryItemCount = dwSize / sizeof(IMAGE_DEBUG_DIRECTORY);
	}
	else if(IMAGE_FILE_MACHINE_AMD64 == m_dwMchine)
	{
		PIMAGE_NT_HEADERS64 pImageNtHeader64 = 
			(PIMAGE_NT_HEADERS64)m_pNtHeader;

		ulDebugDirectoryRVA = 
			pImageNtHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
		DWORD dwSize = 
			pImageNtHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;

		nDirectoryItemCount = dwSize / sizeof(IMAGE_DEBUG_DIRECTORY);
	}
	else
	{
		return;
	}

	ULONG ulDebugDirectoryFOA = RVAToFOA(ulDebugDirectoryRVA) + (ULONG_PTR)m_pImageDosHeader;

	PIMAGE_DEBUG_DIRECTORY pImageDebugDirectory = 
		(PIMAGE_DEBUG_DIRECTORY)ULongToPtr(ulDebugDirectoryFOA);

	for (int i=0; i<nDirectoryItemCount; i++)
	{
		if (IMAGE_DEBUG_TYPE_CODEVIEW == pImageDebugDirectory[i].Type)
		{
			PVOID pDebugInfoRawData = 
				(PVOID) ((ULONG_PTR)m_pImageDosHeader + pImageDebugDirectory[i].PointerToRawData);

			if (pDebugInfoRawData)
			{
				DWORD dwCvSignature = 
					*((PDWORD) pDebugInfoRawData);

				CString strSignature;
				CString strFileName;
				DWORD dwAge = 0;

				switch (dwCvSignature)
				{
				case CV_SIGNATURE_NB09:
				case CV_SIGNATURE_NB10:
					{
						PCV_INFO_PDB20 pCvInfoPdb = 
							((PCV_INFO_PDB20) pDebugInfoRawData);

						strSignature.Format(
							_T("%08X"),
							pCvInfoPdb->dwSignature);

						CStringA strFileNameA = pCvInfoPdb->PdbFileName;
						USES_CONVERSION;

						strFileName = A2T(strFileNameA);
						// 可能为全路径，所以需要取出文件名
						::PathStripPath(strFileName.GetBuffer(MAX_PATH));
						strFileName.ReleaseBuffer();

						dwAge = pCvInfoPdb->dwAge;
					}
					break;
				case CV_SIGNATURE_RSDS:
					{
						PCV_INFO_PDB70 pCvInfoPdb = 
							((PCV_INFO_PDB70) pDebugInfoRawData);

						strSignature.Format(
							_T("%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X"),
							pCvInfoPdb->Signature.Data1, pCvInfoPdb->Signature.Data2, pCvInfoPdb->Signature.Data3,
							pCvInfoPdb->Signature.Data4[0], pCvInfoPdb->Signature.Data4[1],			
							pCvInfoPdb->Signature.Data4[2], pCvInfoPdb->Signature.Data4[3],			
							pCvInfoPdb->Signature.Data4[4], pCvInfoPdb->Signature.Data4[5],			
							pCvInfoPdb->Signature.Data4[6], pCvInfoPdb->Signature.Data4[7]);

						CStringA strFileNameA = pCvInfoPdb->PdbFileName;
						USES_CONVERSION;

						strFileName = A2T(strFileNameA);
						// 可能为全路径，所以需要取出文件名
						::PathStripPath(strFileName.GetBuffer(MAX_PATH));
						strFileName.ReleaseBuffer();

						dwAge = pCvInfoPdb->dwAge;
					}
					break;
				default:
					break;
				}

				if (FALSE == strFileName.IsEmpty() &&
					FALSE == strSignature.IsEmpty())
				{
					strPDBFileName = strFileName;
					strPDBSignature = strSignature;
					dwPDBAge = dwAge;
				}
			}
		}
	}

	return ;
}

//************************************
// Method:    GetPEFileIndex
// FullName:  CPEHelper::GetPEFileIndex
// Access:    public 
// Returns:   VOID
// Qualifier:
// Parameter: CString & strIndex
//			从PE文件中取出如下两个字段拼接成用于从Server拉取二进制模块文件时候的目录索引
//			拼接格式如下：
//				IMAGE_NT_HEADERS.IMAGE_FIEL_HEADER.TimeDateStamp +
//				IMAGE_NT_HEADERS.IMAGE_OPTIONAL_HEADER.SizeOfImage
//************************************
VOID CPEHelper::GetBinFileIndex(CString& strIndex)
{
	strIndex.Empty();
	if (NULL == m_pNtHeader)
	{
		return ;
	}

	DWORD dwTimeDateStamp = 0;
	DWORD dwSizeofImage = 0;

	if (IMAGE_FILE_MACHINE_I386 == m_dwMchine)
	{
		PIMAGE_NT_HEADERS32 pImageNtHeader32 = 
			(PIMAGE_NT_HEADERS32)m_pNtHeader;

		dwTimeDateStamp = pImageNtHeader32->FileHeader.TimeDateStamp;
		dwSizeofImage = pImageNtHeader32->OptionalHeader.SizeOfImage;
	}
	else if(IMAGE_FILE_MACHINE_AMD64 == m_dwMchine)
	{
		PIMAGE_NT_HEADERS64 pImageNtHeader64 = 
			(PIMAGE_NT_HEADERS64)m_pNtHeader;

		dwTimeDateStamp = pImageNtHeader64->FileHeader.TimeDateStamp;
		dwSizeofImage = pImageNtHeader64->OptionalHeader.SizeOfImage;
	}
	else
	{
		return;
	}

	strIndex.Format(
		_T("%08X%X"), dwTimeDateStamp, dwSizeofImage);

	return ;
}

VOID CPEHelper::GetPdbFileIndex(CString& strIndex, CString& strFileName)
{
	strIndex.Empty();
	strFileName.Empty();
	CString strName;
	CString strGuid;
	DWORD dwAge;

	GetPDBInfo(strName, strGuid, dwAge);

	if (strName.IsEmpty() || strGuid.IsEmpty())
	{
		return;
	}

	strFileName = strName;

	strIndex.Format(
		_T("%s%x"), strGuid, dwAge);

	return ;
}
