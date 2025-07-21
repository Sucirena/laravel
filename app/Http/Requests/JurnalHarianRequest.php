<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class JurnalHarianRequest extends FormRequest
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
            'judul' => 'max:50',
        ];
    }

    /**
     * Custom messages for validation errors.
     */
    public function messages(): array
    {
        return [
            'judul.max' => 'Judul jurnal tidak boleh lebih dari 50 karakter.',
        ];
    }
}
