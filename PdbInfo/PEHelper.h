#pragma once
#include <atlstr.h>

#define CV_SIGNATURE_NB10	'01BN'
#define CV_SIGNATURE_NB09	'90BN'
typedef struct _CV_HEADER
{
	DWORD dwSignature;
	DWORD dwOffset;
}CV_HEADER, *PCV_HEADER;
typedef struct _CV_INFO_PDB20
{
	CV_HEADER CvHeader;
	DWORD dwSignature;
	DWORD dwAge;
	BYTE PdbFileName[];
}CV_INFO_PDB20, *PCV_INFO_PDB20;
/************************************************************************/
/*  Member				|Description
 *  CvHeader.Signature	|CodeView signature, equal to ¡°NB10¡±  
 *  CvHeader.Offset		|CodeView offset. Set to 0, because debug information is stored in a separate file.  
 *  Signature			|The time when debug information was created (in seconds since 01.01.1970)  
 *  Age					|Ever-incrementing value, which is initially set to 1 and incremented every time when a part of the PDB file is updated without rewriting the whole file. 
 *  PdbFileName			|Null-terminated name of the PDB file. It can also contain full or partial path to the file.                                                                    */
/************************************************************************/
  
#define CV_SIGNATURE_RSDS   'SDSR'
typedef struct _CV_INFO_PDB70
{
	DWORD dwHeader;
	GUID  Signature;
	DWORD dwAge;
	CHAR  PdbFileName[1];
} CV_INFO_PDB70, *PCV_INFO_PDB70;
/*
 * Member			|Description
 * CvSignature		|CodeView signature, equal to ¡°RSDS¡±  
 * Signature		|A unique identifier, which changes with every rebuild of the executable and PDB file.  
 * Age				|Ever-incrementing value, which is initially set to 1 and incremented every time when a part of the PDB file is updated without rewriting the whole file.  
 * PdbFileName		|Null-terminated name of the PDB file. It can also contain full or partial path to the file.  
 */

class CPEHelper
{
public:
	CPEHelper(void);
	~CPEHelper(void);

	BOOL OpenAndVerify(LPCTSTR pFilePathName);

	VOID GetPDBInfo(CString& strPDBFileName, CString& strPDBSignature, DWORD& dwPDBAge);

	VOID GetBinFileIndex(CString& strIndex);
	VOID GetPdbFileIndex(CString& strIndex, CString& strFileName);

protected:
	VOID InternalClean();
	ULONG RVAToFOA(DWORD dwRva);

private:

	DWORD m_dwMchine;

	HANDLE m_hFile;
	HANDLE m_hFileMapping;
	LPVOID m_pBuffer;

	PIMAGE_DOS_HEADER	m_pImageDosHeader;
	PIMAGE_FILE_HEADER	m_pImageFileHeader;

	LPVOID				m_pNtHeader;
};