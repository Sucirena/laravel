<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class AktivitasPositifRequest extends FormRequest
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
        return [
            'nama' => 'required|string|max:255',
            'gambar' => $this->isMethod('post') 
                ? 'required|image|mimes:jpeg,png,jpg,svg|max:2048' // Required saat store
                : 'nullable|image|mimes:jpeg,png,jpg,svg|max:2048',  // Nullable saat update
        ];
    }

    /**
     * Pesan kesalahan yang disesuaikan untuk setiap aturan validasi.
     */
    public function messages(): array
    {
        return [
            'nama.required' => 'Nama aktivitas wajib diisi.',
            'nama.max' => 'Nama aktivitas tidak boleh lebih dari 255 karakter.',
            'gambar.required' => 'Gambar aktivitas wajib diunggah.',
            'gambar.image' => 'File yang diunggah harus berupa gambar.',
            'gambar.mimes' => 'Format gambar harus berupa jpeg, png, jpg, atau gif.',
            'gambar.max' => 'Ukuran gambar tidak boleh lebih dari 2 MB.',
        ];
    }
}
