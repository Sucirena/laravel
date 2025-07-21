<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class RegisterRequest extends FormRequest
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
    public function rules()
    {
        return [
            'nama' => 'required|string|max:255',
            'email' => 'required|email|unique:user,email',
            'jenis_kelamin' => 'required|string',
            'tanggal_lahir' => 'required|date',
            'password' => 'required|string|min:8|confirmed',
        ];
    }

    /**
     * Pesan kesalahan khusus untuk validasi.
     *
     * @return array
     */
    public function messages()
    {
        return [
            'nama.required' => 'Nama wajib diisi.',
            'email.required' => 'Email wajib diisi.',
            'email.email' => 'Email harus dalam format yang benar.',
            'email.unique' => 'Email sudah digunakan.',
            'jenis_kelamin.required' => 'Jenis kelamin wajib dipilih.',
            'tanggal_lahir.required' => 'Tanggal lahir wajib diisi.',
            'password.required' => 'Password wajib diisi.',
            'password.min' => 'Password harus memiliki minimal 8 karakter.',
            'password.confirmed' => 'Password konfirmasi tidak cocok.',
        ];
    }
}
