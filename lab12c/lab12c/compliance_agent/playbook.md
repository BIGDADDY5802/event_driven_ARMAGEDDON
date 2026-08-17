Stage One
Load the Control Library

The first thing our Compliance Agent does is open

        controls.json

Think of this file as a book.

Inside that book are all the security controls we care about.

The Python code does not contain the compliance rules.

Instead, it reads them.

That makes our system flexible.

If next year we add PCI or HIPAA...

we update the book.

We do not rewrite the engine.

Stage Two
Select Controls

Suppose we only want to evaluate NIST.

The agent ignores everything else.

        controls.json
        
        ↓
        
        NIST Controls
        
        ↓
        
        Evaluate

Stage Three
Evaluate Each Control

There aren't any. So Instead...

        for control in controls:
        
            evaluate(control)


Every control tells Python how to evaluate it.

The engine doesn't care whether the control is WAF, Lambda, S3, or SNS.

That's the beauty of the design.

Validators

Each control contains something like

        "type":"table_exists"

The engine says

"Oh..."

"I know how to validate a DynamoDB table."

Later

        "type":"lambda_exists"

"Oh..."

"I know that one too."

The engine never changes.

We simply teach it more validators over time.

Why Validators Matter

Imagine hiring electricians.

You don't teach every electrician every building.

You teach them

how to use a multimeter.

Now they can test any building.

Validators work exactly the same way.

They are reusable skills.


Evidence

After validating a control we immediately write evidence.

Not later.

Immediately.

Why?

Because six months from now someone may ask

"Why did Control 17 pass?"

The PDF won't answer that.

The evidence record will.

Evidence becomes history.

Why We Don't Wait Until the End? 

Imagine losing power halfway through the report.
Without evidence records... everything disappears.

Instead


        Control
        
        ↓
        
        Evaluate
        
        ↓
        
        Write Evidence
        
        ↓
        
        Next Control

If Lambda crashes...
you've still preserved everything already evaluated.
That's much more resilient.

Compliance Score

Now we calculate

        PASS
        
        FAIL
        
        REVIEW

Nothing magical. Just counting.
Students often expect AI here.
No.
Math is better.
Math is deterministic.
AI isn't.


Bedrock Finally Arrives

Notice something.

Bedrock doesn't see AWS.

Bedrock doesn't inspect DynamoDB.

Bedrock doesn't inspect WAF.

Python already did all of that.

Bedrock receives something much simpler.


        Control 1
        
        PASS
        
        Observation
        
        ...
        
        Control 2
        
        FAIL
        
        Observation
        
        ...


That's all.

This dramatically reduces hallucinations.


PDF Generation

The PDF is simply another view of the report.

The JSON came first.

The PDF is built from the JSON.

Not the other way around.

That means

        JSON
        
        ↓
        
        PDF

always stay synchronized.


Upload

Finally both reports go to


        ChewbaccaS3
        
        Compliance
        
        PDF
        
        JSON

One for humans. One for machines.

Why We Store JSON

Students often ask

"Why not just the PDF?"

Because computers don't read PDFs very well.

Future systems can easily read


        JSON
        
        ↓
        
        Glue
        
        ↓
        
        Athena
        
        ↓
        
        QuickSight
        
        ↓
        
        Future AI Agents

The PDF is for people. The JSON is for platforms.

What the Compliance Agent Never Does

It never says "We are PCI compliant."

It never says "You passed the audit."

It never says "You are secure."

It only says

    "Based on the evidence currently available, these controls passed, failed, or require review."

That's an important distinction in both engineering and compliance.

The Entire Story

When you feel lost...

remember this picture.

        Load the Book
        (controls.json)
        
        ↓
        
        Choose Controls
        
        ↓
        
        Evaluate Controls
        
        ↓
        
        Save Evidence
        
        ↓
        
        Calculate Score
        
        ↓
        
        Bedrock Explains
        
        ↓
        
        Generate PDF
        
        ↓
        
        Generate JSON
        
        ↓
        
        Chewbacca Guards the Archive







You need to install compliance_agent.py


New DynamoDB Table: compliance-evidence

Each item becomes evidence.

Examle

    
    {
      "evidence_id":"uuid",
    
      "framework":"NIST",
    
      "control":"DE.AE-03",
    
      "service":"AWS WAF",
    
      "status":"PASS",
    
      "observation":
    
      "AWS WAF blocked malicious requests.",
    
      "source":
    
      "waf-events",
    
      "generated":
    
      "2026-07-28T13:02:11Z"
    }

Another Table: compliance-findings

It should store as follows:

    {
        "finding_id":"uuid",
    
        "framework":"CIS",
    
        "severity":"Medium",
    
        "control":"3.3",
    
        "status":"Needs Review",
    
        "recommendation":
    
        "CloudTrail should be enabled."
    }

