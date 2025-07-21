<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class DiskusiRequest extends FormRequest
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
            'judul' => 'required|string|max:255',
            'isi' => 'required|string',
            'gambar.*' => 'nullable|image|mimes:jpeg,png,jpg|max:2048',
        ];
    }

    public function messages()
    {
        return [
            'judul.required' => 'Judul diskusi wajib diisi.',
            'isi.required' => 'Isi diskusi wajib diisi.',
            'gambar.*.image' => 'File yang diunggah harus berupa gambar.',
            'gambar.*.mimes' => 'Format gambar harus jpeg, png, jpg, gif, atau svg.',
            'gambar.*.max' => 'Ukuran gambar tidak boleh lebih dari 2MB.',
        ];
    }
}
