<?php

namespace AbuseIO\Parsers;

class Junkemailfilter extends Parser
{
    /**
     * Create a new Blocklistde instance
     */
    public function __construct($parsedMail, $arfMail)
    {
        parent::__construct($parsedMail, $arfMail, $this);
    }

    /**
     * Parse attachments
     * @return Array    Returns array with failed or success data
     *                  (See parser-common/src/Parser.php) for more info.
     */
    public function parse()
    {
        if ($this->arfMail !== false) {
            $this->feedName = 'default';

            // If feed is known and enabled, validate data and save report
            if ($this->isKnownFeed() && $this->isEnabledFeed()) {

                if (preg_match_all('/([\w\-]+): (.*)[ ]*\r?\n/', $this->arfMail['report'], $matches)) {
                    $report = array_combine($matches[1], $matches[2]);

                    // Sanity check
                    if (($this->hasRequiredFields($report) === true) &&
                        ($report['Feedback-Type'] == 'abuse')
                    ) {
                        // Event has all requirements met, filter and add!
                        $report = $this->applyFilters($report);

                        $report['evidence'] = $this->arfMail['evidence'];

                        $this->events[] = [
                            'source'        => config("{$this->configBase}.parser.name"),
                            'ip'            => $report['Source-IP'],
                            'domain'        => false,
                            'uri'           => false,
                            'class'         => config("{$this->configBase}.feeds.{$this->feedName}.class"),
                            'type'          => config("{$this->configBase}.feeds.{$this->feedName}.type"),
                            'timestamp'     => strtotime($report['Received-Date']),
                            'information'   => json_encode($report),
                        ];

                    }
                } else {
                    $this->warningCount++;
                }
            }
        } else {
            $this->warningCount++;
        }

        return $this->success();
    }
}

