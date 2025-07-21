<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class UpdateUserRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        $rules = [
            'role' => 'required|in:admin,tenaga ahli,pasien', // Validasi role
            'password' => 'nullable|min:8|max:255', // Password minimal 8 karakter
            'nama' => 'required|string|max:50', // Nama tidak boleh kosong
            'jenis_kelamin' => 'required|in:laki laki,perempuan', // Jenis kelamin hanya boleh 'laki laki' atau 'perempuan'
            'tanggal_lahir' => 'required|date', // Tanggal lahir valid
            'foto_profil' => 'nullable|image|mimes:jpeg,png,jpg|max:2048', // Opsional untuk foto profil
        ];

        // Tentukan aturan berdasarkan role
        if ($this->input('role') === 'admin') {
            return array_merge($rules, [
                'admin_role' => 'required|in:superadmin,content admin', // Validasi role admin
            ]);
        } elseif ($this->input('role') === 'tenaga ahli') {
            return array_merge($rules, [
                'nomor_str' => 'required|string|max:20', // Nomor STR wajib diisi
                'spesialisasi' => 'required|string|max:50', // Spesialisasi wajib
                'jadwal_aktif' => 'required|string|max:255', // Jadwal konsultasi wajib
                'lokasi_praktik' => 'nullable|string|max:255', // Lokasi praktik bisa opsional
                'biaya_konsultasi' => 'required|numeric|min:0', // Biaya konsultasi wajib dan minimal 0
            ]);
        } elseif ($this->input('role') === 'pasien') {
            return array_merge($rules, [
                'deskripsi_diri' => 'nullable|string', // Deskripsi diri bisa kosong
            ]);
        }

        // Jika role tidak sesuai, tetap pakai aturan umum
        return $rules;
    }

    /**
     * Custom error messages.
     */
    public function messages()
    {
        return [
            'role.required' => 'Role wajib diisi.',
            'role.in' => 'Role harus salah satu dari: admin, tenaga ahli, pasien.',
            'nama.required' => 'Nama lengkap wajib diisi.',
            'nama.string' => 'Nama harus berupa teks.',
            'nama.max' => 'Nama tidak boleh lebih dari 50 karakter.',
            'jenis_kelamin.required' => 'Jenis kelamin wajib diisi.',
            'jenis_kelamin.in' => 'Jenis kelamin harus berupa "laki laki" atau "perempuan".',
            'tanggal_lahir.required' => 'Tanggal lahir wajib diisi.',
            'tanggal_lahir.date' => 'Tanggal lahir harus berupa tanggal yang valid.',
            'password.min' => 'Password minimal 8 karakter.',
            'password.max' => 'Password tidak boleh lebih dari 255 karakter.',
            'foto_profil.image' => 'Foto profil harus berupa gambar.',
            'foto_profil.mimes' => 'Foto profil harus berformat JPEG, PNG, atau JPG.',
            'foto_profil.max' => 'Foto profil tidak boleh lebih dari 2 MB.',
            
            'admin_role.required' => 'Role admin wajib diisi.',
            'admin_role.in' => 'Role admin harus berupa "superadmin" atau "content admin".',
            
            'nomor_str.required' => 'Nomor STR wajib diisi untuk tenaga ahli.',
            'nomor_str.string' => 'Nomor STR harus berupa teks.',
            'nomor_str.max' => 'Nomor STR tidak boleh lebih dari 20 karakter.',
            'spesialisasi.required' => 'Spesialisasi wajib diisi untuk tenaga ahli.',
            'spesialisasi.string' => 'Spesialisasi harus berupa teks.',
            'spesialisasi.max' => 'Spesialisasi tidak boleh lebih dari 50 karakter.',
            'jadwal_aktif.required' => 'Jadwal aktif wajib diisi untuk tenaga ahli.',
            'jadwal_aktif.string' => 'Jadwal aktif harus berupa teks.',
            'jadwal_aktif.max' => 'Jadwal aktif tidak boleh lebih dari 255 karakter.',
            'lokasi_praktik.string' => 'Lokasi praktik harus berupa teks.',
            'lokasi_praktik.max' => 'Lokasi praktik tidak boleh lebih dari 255 karakter.',
            'biaya_konsultasi.required' => 'Biaya konsultasi wajib diisi untuk tenaga ahli.',
            'biaya_konsultasi.numeric' => 'Biaya konsultasi harus berupa angka.',
            'biaya_konsultasi.min' => 'Biaya konsultasi minimal 0.',

            'deskripsi_diri.string' => 'Deskripsi diri harus berupa teks.',
        ];
    }
}
