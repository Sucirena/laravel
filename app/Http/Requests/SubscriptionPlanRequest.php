<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class SubscriptionPlanRequest extends FormRequest
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
            'name' => 'required|string|max:255',
            'price' => 'required|numeric|min:0',
            'duration' => 'required|integer|min:1',
        ];
    }

    /**
     * Get custom messages for validation errors.
     */
    public function messages(): array
    {
        return [
            'name.required' => 'Nama paket wajib diisi.',
            'name.string' => 'Nama paket harus berupa teks.',
            'name.max' => 'Nama paket tidak boleh lebih dari 255 karakter.',
            'price.required' => 'Harga paket wajib diisi.',
            'price.numeric' => 'Harga paket harus berupa angka.',
            'price.min' => 'Harga paket tidak boleh kurang dari 0.',
            'duration.required' => 'Durasi paket wajib diisi.',
            'duration.integer' => 'Durasi paket harus berupa angka bulat.',
            'duration.min' => 'Durasi paket minimal 1 hari.',
        ];
    }
}
