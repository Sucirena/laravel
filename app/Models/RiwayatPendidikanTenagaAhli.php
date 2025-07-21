<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class RiwayatPendidikanTenagaAhli extends Model
{
    use HasFactory;

    // Tentukan tabel yang digunakan oleh model ini
    protected $table = 'riwayat_pendidikan_tenaga_ahli';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'id_tenaga_ahli',
        'keterangan',
    ];

    /**
     * Define relationship to the TenagaAhli model.
     * Setiap riwayat pendidikan berhubungan dengan satu tenaga ahli (TenagaAhli).
     */
    public function tenagaAhli()
    {
        return $this->belongsTo(TenagaAhli::class, 'id_tenaga_ahli');
    }
    
    public $timestamps = false;
}
