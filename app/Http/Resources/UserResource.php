<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class UserResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'role' => $this->role,
            'email' => $this->email,
            'password' => $this->password,
            'nama' => $this->nama,
            'jenis_kelamin' => $this->jenis_kelamin,
            'tanggal_lahir' => $this->tanggal_lahir ? $this->tanggal_lahir->format('d/m/Y') : null,
            'foto_profil' => $this->foto_profil,
            'created_at' => $this->created_at ? $this->created_at->format('d/m/Y H:i:s') : null,
            'updated_at' => $this->updated_at ? $this->updated_at->format('d/m/Y H:i:s') : null,

            'admin' => new AdminResource($this->whenLoaded('admin')),
            'tenaga_ahli' => new TenagaAhliResource($this->whenLoaded('tenagaAhli')),
            'pasien' => new PasienResource($this->whenLoaded('pasien')),
        ];
    }
}
