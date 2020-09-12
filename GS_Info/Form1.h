#pragma once
#include <string>

//Module Flags
#define MODULE_SUSPICIOUS		1

//Memory Flags
#define MEMORY_SUSPICIOUS 		2

//Integrity Flags
#define INTEGRITY_VIOLATION		3

//Kernel Flags
#define DRIVER_BLACKLISTED		4
#define KERNEL_MODIFICATION		5

//Process
#define PROGRAM_SUSPICIOUS		6

//System
#define SYSTEM_TESTMODE			7
#define SYSTEM_NO_PATCHGUARD	8
#define SYSTEM_VM				9
#define SYSTEM_HYPERVISOR		10

#define DEBUGGER_PRESENT		11


struct _Log
{
	unsigned int msgCode;
	char* extraInfo;
};


_Log GetInfo();

namespace CppCLRWinformsProjekt {


	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;


	/// <summary>
	/// Zusammenfassung für Form1
	/// </summary>
	public ref class Form1 : public System::Windows::Forms::Form
	{
	public:
		Form1(void)
		{
			InitializeComponent();
			//
			//TODO: Konstruktorcode hier hinzufügen.
			//
		}

	protected:
		/// <summary>
		/// Verwendete Ressourcen bereinigen.
		/// </summary>
		~Form1()
		{
			if (components)
			{
				delete components;
			}
		}

	private: System::Windows::Forms::RichTextBox^ richTextBox1;
	private: System::Windows::Forms::GroupBox^ groupBox1;
	private: System::Windows::Forms::PictureBox^ pictureBox1;


	protected:

	private:
		/// <summary>
		/// Erforderliche Designervariable.
		/// </summary>
		System::ComponentModel::Container ^components;

#pragma region Windows Form Designer generated code
		/// <summary>
		/// Erforderliche Methode für die Designerunterstützung.
		/// Der Inhalt der Methode darf nicht mit dem Code-Editor geändert werden.
		/// </summary>
		void InitializeComponent(void)
		{
			this->richTextBox1 = (gcnew System::Windows::Forms::RichTextBox());
			this->groupBox1 = (gcnew System::Windows::Forms::GroupBox());
			this->pictureBox1 = (gcnew System::Windows::Forms::PictureBox());
			this->groupBox1->SuspendLayout();
			(cli::safe_cast<System::ComponentModel::ISupportInitialize^>(this->pictureBox1))->BeginInit();
			this->SuspendLayout();
			// 
			// richTextBox1
			// 
			this->richTextBox1->Dock = System::Windows::Forms::DockStyle::Fill;
			this->richTextBox1->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9.75F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->richTextBox1->ForeColor = System::Drawing::Color::Red;
			this->richTextBox1->Location = System::Drawing::Point(3, 17);
			this->richTextBox1->Name = L"richTextBox1";
			this->richTextBox1->Size = System::Drawing::Size(331, 141);
			this->richTextBox1->TabIndex = 1;
			this->richTextBox1->Text = L"";
			// 
			// groupBox1
			// 
			this->groupBox1->Controls->Add(this->richTextBox1);
			this->groupBox1->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 9, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(0)));
			this->groupBox1->Location = System::Drawing::Point(165, 2);
			this->groupBox1->Name = L"groupBox1";
			this->groupBox1->Size = System::Drawing::Size(337, 161);
			this->groupBox1->TabIndex = 2;
			this->groupBox1->TabStop = false;
			this->groupBox1->Text = L"Information Log:";
			// 
			// pictureBox1
			// 
			this->pictureBox1->ImageLocation = L"C:\\Users\\Kilian\\Downloads\\pic.png";
			this->pictureBox1->Location = System::Drawing::Point(-2, 10);
			this->pictureBox1->Name = L"pictureBox1";
			this->pictureBox1->Size = System::Drawing::Size(167, 153);
			this->pictureBox1->SizeMode = System::Windows::Forms::PictureBoxSizeMode::StretchImage;
			this->pictureBox1->TabIndex = 3;
			this->pictureBox1->TabStop = false;
			// 
			// Form1
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(6, 13);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->ClientSize = System::Drawing::Size(508, 167);
			this->Controls->Add(this->pictureBox1);
			this->Controls->Add(this->groupBox1);
			this->FormBorderStyle = System::Windows::Forms::FormBorderStyle::FixedSingle;
			this->Name = L"Form1";
			this->ShowIcon = false;
			this->StartPosition = System::Windows::Forms::FormStartPosition::CenterScreen;
			this->Text = L"GameShield Online Game Security";
			this->TopMost = true;
			this->TransparencyKey = System::Drawing::Color::Silver;
			this->Load += gcnew System::EventHandler(this, &Form1::Form1_Load);
			this->groupBox1->ResumeLayout(false);
			(cli::safe_cast<System::ComponentModel::ISupportInitialize^>(this->pictureBox1))->EndInit();
			this->ResumeLayout(false);

		}
#pragma endregion
	private: System::Void pictureBox1_Click(System::Object^ sender, System::EventArgs^ e) {
	}
private: System::Void Form1_Load(System::Object^ sender, System::EventArgs^ e) {
	richTextBox1->ReadOnly = true;

	_Log Log = GetInfo();

	/*String^ sExtraInfo = gcnew String(Log.extraInfo.c_str());*/
	richTextBox1->ForeColor = Color::Red;

	switch (Log.msgCode)
	{
	case MODULE_SUSPICIOUS:
		richTextBox1->Text = "[INFO] Suspicious or unallowed module detected";
		/*richTextBox1->AppendText(Environment::NewLine + sExtraInfo);*/
		break;
	case MEMORY_SUSPICIOUS:
		richTextBox1->Text = "[INFO] Suspicious or unknown memory changes detected";
	/*	richTextBox1->AppendText(Environment::NewLine + sExtraInfo);*/
		break;
	case INTEGRITY_VIOLATION:
		richTextBox1->Text = "[INFO] Integrity check failed";
		/*richTextBox1->AppendText(Environment::NewLine + sExtraInfo);*/
		break;
	case DRIVER_BLACKLISTED:
		richTextBox1->Text = "[INFO] Suspicious or unallowed kernel module detected";
		/*richTextBox1->AppendText(Environment::NewLine + sExtraInfo);*/
		break;
	case PROGRAM_SUSPICIOUS:
		richTextBox1->Text = "[INFO] Suspicious or unallowed program detected";
		/*richTextBox1->AppendText(Environment::NewLine + sExtraInfo);*/
		break;
	default:
		richTextBox1->Text = "[INFO] Unknown error encountered " + Log.msgCode;
		/*richTextBox1->AppendText(Environment::NewLine + sExtraInfo);*/
		break;
	}
}
};
}
