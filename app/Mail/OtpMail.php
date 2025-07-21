<?php

namespace App\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;

class OtpMail extends Mailable
{
    use Queueable, SerializesModels;

    public $otpCode;

    /**
     * Create a new message instance.
     */
    public function __construct($otpCode)
    {
        $this->otpCode = $otpCode;
    }

    /**
     * Build the message.
     */
    public function build()
    {
        return $this->markdown('emails.otp')
            ->subject('Email OTP Code')
            ->with(['otpCode' => $this->otpCode]);
    }
}
