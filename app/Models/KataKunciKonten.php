<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class KataKunciKonten extends Model
{
    use HasFactory;

    protected $table = 'kata_kunci_konten';

    protected $fillable = [
        'id_konten',
        'nama',
    ];

    /**
     * Relasi dengan model KontenEdukatif.
     */
    public function kontenEdukatif()
    {
        return $this->belongsTo(KontenEdukatif::class, 'id_konten');
    }

    public $timestamps = false;
}
